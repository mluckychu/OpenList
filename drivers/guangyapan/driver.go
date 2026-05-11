package guangyapan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

const (
	accountBaseURL = "https://account.guangyapan.com"
	apiBaseURL     = "https://api.guangyapan.com"
	defaultClient  = "aMe-8VSlkrbQXpUR"
)

type GuangYaPan struct {
	model.Storage
	Addition

	accountClient *resty.Client
	apiClient     *resty.Client
}

func (d *GuangYaPan) Config() driver.Config {
	return config
}

func (d *GuangYaPan) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *GuangYaPan) Init(ctx context.Context) error {
	d.ClientID = strings.TrimSpace(d.ClientID)
	if d.ClientID == "" {
		d.ClientID = defaultClient
	}
	d.DeviceID = normalizeDeviceID(d.DeviceID)
	if d.DeviceID == "" {
		d.DeviceID = randomDeviceID()
	}
	if d.PageSize <= 0 {
		d.PageSize = 100
	}
	if d.OrderBy < 0 {
		d.OrderBy = 3
	}
	if d.SortType != 0 && d.SortType != 1 {
		d.SortType = 1
	}

	d.AccessToken = strings.TrimSpace(d.AccessToken)
	d.RefreshToken = strings.TrimSpace(d.RefreshToken)
	d.PhoneNumber = strings.TrimSpace(d.PhoneNumber)
	d.VerifyCode = strings.TrimSpace(d.VerifyCode)
	d.CaptchaToken = strings.TrimSpace(d.CaptchaToken)
	d.VerificationID = strings.TrimSpace(d.VerificationID)

	d.accountClient = base.NewRestyClient().
		SetBaseURL(accountBaseURL).
		SetHeader("Accept", "application/json, text/plain, */*").
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Device-Model", "chrome%2F147.0.0.0").
		SetHeader("X-Device-Name", "PC-Chrome").
		SetHeader("X-Device-Sign", "wdi10."+d.DeviceID+"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").
		SetHeader("X-Net-Work-Type", "NONE").
		SetHeader("X-OS-Version", "MacIntel").
		SetHeader("X-Platform-Version", "1").
		SetHeader("X-Protocol-Version", "301").
		SetHeader("X-Provider-Name", "NONE").
		SetHeader("X-SDK-Version", "9.0.2").
		SetHeader("X-Client-Id", d.ClientID).
		SetHeader("X-Client-Version", "0.0.1").
		SetHeader("X-Device-Id", d.DeviceID)
	if d.CaptchaToken != "" {
		d.accountClient.SetHeader("X-Captcha-Token", d.CaptchaToken)
	}

	d.apiClient = base.NewRestyClient().
		SetBaseURL(apiBaseURL).
		SetHeader("Accept", "application/json, text/plain, */*").
		SetHeader("Content-Type", "application/json").
		SetHeader("Did", d.DeviceID).
		SetHeader("Dt", "4")

	// Priority: access_token -> refresh_token -> sms login.
	if d.AccessToken != "" {
		if err := d.validateToken(ctx); err == nil {
			return nil
		}
		d.AccessToken = ""
	}
	if d.RefreshToken != "" {
		if err := d.refreshToken(ctx); err == nil {
			if err2 := d.validateToken(ctx); err2 == nil {
				return nil
			}
		}
	}
	// Two-stage SMS flow:
	// 1) phone only + send_code=true: send code and cache verification_id (do not fail init).
	// 2) phone + verify_code: complete login and save tokens.
	if d.PhoneNumber != "" {
		if d.canSMSLogin() {
			if err := d.loginBySMSCode(ctx); err != nil {
				return err
			}
			return d.validateToken(ctx)
		}
		if d.SendCode {
			d.setTempStatus("SMS sending in progress...")
			if err := d.prepareSMSCode(ctx); err != nil {
				d.setTempStatus(fmt.Sprintf("SMS send failed: %v. Please check captcha/meta and set send_code=true to retry.", err))
				log.Warnf("guangyapan: prepare sms code failed: %v", err)
			} else {
				d.setTempStatus("SMS sent successfully. Please fill verify_code and save to complete login.")
			}
		}
		return nil
	}
	return errors.New("login failed: provide a valid access_token, or refresh_token, or phone_number + verify_code + captcha_token")
}

func (d *GuangYaPan) Drop(ctx context.Context) error {
	return nil
}

func (d *GuangYaPan) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if err := d.ensureAccessToken(ctx); err != nil {
		return nil, err
	}

	parentID := dir.GetID()
	if parentID == d.RootFolderID {
		parentID = ""
	}

	res := make([]model.Obj, 0, d.PageSize)
	for page := 0; ; page++ {
		var resp listResp
		body := map[string]any{
			"parentId":  parentID,
			"page":      page,
			"pageSize":  d.PageSize,
			"orderBy":   d.OrderBy,
			"sortType":  d.SortType,
			"fileTypes": []int{},
		}
		if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/file/get_file_list", body, &resp); err != nil {
			return nil, err
		}
		for _, item := range resp.Data.List {
			res = append(res, &model.Object{
				ID:       item.FileID,
				Path:     parentID,
				Name:     item.FileName,
				Size:     item.FileSize,
				Modified: unixOrZero(item.UTime),
				Ctime:    unixOrZero(item.CTime),
				IsFolder: item.ResType == 2,
			})
		}
		if len(resp.Data.List) < d.PageSize {
			break
		}
		if resp.Data.Total > 0 && len(res) >= resp.Data.Total {
			break
		}
	}
	return res, nil
}

func (d *GuangYaPan) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if file.IsDir() {
		return nil, errs.NotFile
	}
	if err := d.ensureAccessToken(ctx); err != nil {
		return nil, err
	}

	var resp downloadResp
	if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/get_res_download_url", map[string]any{
		"fileId": file.GetID(),
	}, &resp); err != nil {
		return nil, err
	}

	urlStr := strings.TrimSpace(resp.Data.SignedURL)
	if urlStr == "" {
		urlStr = strings.TrimSpace(resp.Data.DownloadURL)
	}
	if urlStr == "" {
		return nil, errors.New("empty download url")
	}
	return &model.Link{URL: urlStr}, nil
}

func (d *GuangYaPan) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	if err := d.ensureAccessToken(ctx); err != nil {
		return err
	}

	name := strings.TrimSpace(dirName)
	if name == "" {
		return errors.New("dir name is empty")
	}

	parentID := parentDir.GetID()
	if parentID == d.RootFolderID {
		parentID = ""
	}

	var out createDirResp
	if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/file/create_dir", map[string]any{
		"parentId": parentID,
		"dirName":  name,
	}, &out); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(out.Msg), "success") {
		return fmt.Errorf("make dir failed: %s", strings.TrimSpace(out.Msg))
	}
	return nil
}

func (d *GuangYaPan) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	if err := d.ensureAccessToken(ctx); err != nil {
		return err
	}

	fileID := strings.TrimSpace(srcObj.GetID())
	if fileID == "" {
		return errors.New("file id is empty")
	}
	name := strings.TrimSpace(newName)
	if name == "" {
		return errors.New("new name is empty")
	}

	var out commonResp
	if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/file/rename", map[string]any{
		"fileId":  fileID,
		"newName": name,
	}, &out); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(out.Msg), "success") {
		return fmt.Errorf("rename failed: %s", strings.TrimSpace(out.Msg))
	}
	return nil
}

func (d *GuangYaPan) Remove(ctx context.Context, obj model.Obj) error {
	if err := d.ensureAccessToken(ctx); err != nil {
		return err
	}

	fileID := strings.TrimSpace(obj.GetID())
	if fileID == "" {
		return errors.New("file id is empty")
	}

	var del deleteResp
	if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/file/delete_file", map[string]any{
		"fileIds": []string{fileID},
	}, &del); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(del.Msg), "success") {
		return fmt.Errorf("delete failed: %s", strings.TrimSpace(del.Msg))
	}

	taskID := strings.TrimSpace(del.Data.TaskID)
	if taskID == "" {
		return nil
	}
	return d.waitTaskDone(ctx, taskID)
}

func (d *GuangYaPan) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	if err := d.ensureAccessToken(ctx); err != nil {
		return err
	}

	fileID := strings.TrimSpace(srcObj.GetID())
	if fileID == "" {
		return errors.New("file id is empty")
	}
	parentID := dstDir.GetID()
	if parentID == d.RootFolderID {
		parentID = ""
	}

	var out deleteResp
	if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/file/move_file", map[string]any{
		"fileIds":  []string{fileID},
		"parentId": parentID,
	}, &out); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(out.Msg), "success") {
		return fmt.Errorf("move failed: %s", strings.TrimSpace(out.Msg))
	}
	taskID := strings.TrimSpace(out.Data.TaskID)
	if taskID == "" {
		return nil
	}
	return d.waitTaskDone(ctx, taskID)
}

func (d *GuangYaPan) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	if err := d.ensureAccessToken(ctx); err != nil {
		return err
	}

	fileID := strings.TrimSpace(srcObj.GetID())
	if fileID == "" {
		return errors.New("file id is empty")
	}
	parentID := dstDir.GetID()
	if parentID == d.RootFolderID {
		parentID = ""
	}

	var out deleteResp
	if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/file/copy_file", map[string]any{
		"fileIds":  []string{fileID},
		"parentId": parentID,
	}, &out); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(out.Msg), "success") {
		return fmt.Errorf("copy failed: %s", strings.TrimSpace(out.Msg))
	}
	taskID := strings.TrimSpace(out.Data.TaskID)
	if taskID == "" {
		return nil
	}
	return d.waitTaskDone(ctx, taskID)
}

func (d *GuangYaPan) Put(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress) error {
	if err := d.ensureAccessToken(ctx); err != nil {
		return err
	}
	if file == nil {
		return errors.New("file is nil")
	}
	if file.GetSize() < 0 {
		return errors.New("invalid file size")
	}
	name := strings.TrimSpace(file.GetName())
	if name == "" {
		return errors.New("file name is empty")
	}

	parentID := dstDir.GetID()
	if parentID == d.RootFolderID {
		parentID = ""
	}

	token, code, err := d.getUploadToken(ctx, parentID, name, file.GetSize())
	if err != nil {
		return err
	}
	taskID := strings.TrimSpace(token.TaskID)
	if code == 156 {
		if taskID == "" {
			return errors.New("instant upload returns empty task id")
		}
		return d.waitUploadTaskInfo(ctx, taskID)
	}

	if token.ObjectPath == "" || token.BucketName == "" || token.EndPoint == "" || token.AccessKeyID == "" || token.SecretAccessKey == "" {
		return errors.New("upload token is incomplete")
	}

	ossEndpoint := normalizeOSSEndpoint(token.EndPoint, token.BucketName)
	client, err := oss.New(ossEndpoint, token.AccessKeyID, token.SecretAccessKey, oss.SecurityToken(token.SessionToken))
	if err != nil {
		return fmt.Errorf("create oss client failed: %w", err)
	}
	bucket, err := client.Bucket(token.BucketName)
	if err != nil {
		return fmt.Errorf("create oss bucket failed: %w", err)
	}

	if file.GetSize() == 0 {
		if err := bucket.PutObject(token.ObjectPath, strings.NewReader("")); err != nil {
			return err
		}
	} else {
		if err := d.multipartUploadToOSS(ctx, bucket, token.ObjectPath, file, up); err != nil {
			return err
		}
	}

	if taskID == "" {
		return nil
	}
	return d.waitUploadTaskInfo(ctx, taskID)
}

func (d *GuangYaPan) ensureAccessToken(ctx context.Context) error {
	if strings.TrimSpace(d.AccessToken) != "" {
		return nil
	}
	if strings.TrimSpace(d.RefreshToken) == "" {
		if d.canSMSLogin() {
			return d.loginBySMSCode(ctx)
		}
		if d.PhoneNumber != "" {
			return errors.New("not logged in yet: please fill verify_code and save storage to finish SMS login")
		}
		return errors.New("access token is empty")
	}
	return d.refreshToken(ctx)
}

func (d *GuangYaPan) validateToken(ctx context.Context) error {
	var me userMeResp
	resp, err := d.accountClient.R().
		SetContext(ctx).
		SetHeader("Authorization", "Bearer "+d.AccessToken).
		SetResult(&me).
		Get("/v1/user/me")
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("validate token failed: status=%d body=%s", resp.StatusCode(), resp.String())
	}
	if strings.TrimSpace(me.Sub) == "" {
		return errors.New("validate token failed: empty user sub")
	}
	return nil
}

func (d *GuangYaPan) refreshToken(ctx context.Context) error {
	if strings.TrimSpace(d.RefreshToken) == "" {
		return errors.New("refresh_token is empty")
	}

	var out tokenResp
	resp, err := d.accountClient.R().
		SetContext(ctx).
		SetBody(map[string]any{
			"client_id":     d.ClientID,
			"grant_type":    "refresh_token",
			"refresh_token": d.RefreshToken,
		}).
		SetResult(&out).
		Post("/v1/auth/token")
	if err != nil {
		return err
	}
	if resp.IsError() || out.Error != "" || strings.TrimSpace(out.AccessToken) == "" {
		errMsg := strings.TrimSpace(out.ErrorDesc)
		if errMsg == "" {
			errMsg = strings.TrimSpace(out.Error)
		}
		if errMsg == "" {
			errMsg = strings.TrimSpace(resp.String())
		}
		if errMsg == "" {
			errMsg = fmt.Sprintf("status=%d", resp.StatusCode())
		}
		return fmt.Errorf("refresh token failed: %s", errMsg)
	}

	d.AccessToken = strings.TrimSpace(out.AccessToken)
	if strings.TrimSpace(out.RefreshToken) != "" {
		d.RefreshToken = strings.TrimSpace(out.RefreshToken)
	}
	op.MustSaveDriverStorage(d)
	return nil
}

func (d *GuangYaPan) canSMSLogin() bool {
	return d.PhoneNumber != "" && d.VerifyCode != ""
}

func (d *GuangYaPan) loginBySMSCode(ctx context.Context) error {
	verificationID := strings.TrimSpace(d.VerificationID)
	if verificationID == "" {
		var err error
		verificationID, err = d.requestVerificationID(ctx)
		if err != nil {
			return err
		}
	}

	var step2 verifyResp
	resp, err := d.accountClient.R().
		SetContext(ctx).
		SetBody(map[string]any{
			"verification_id":   verificationID,
			"verification_code": d.VerifyCode,
			"client_id":         d.ClientID,
		}).
		SetResult(&step2).
		Post("/v1/auth/verification/verify")
	if err != nil {
		return err
	}
	if resp.IsError() || step2.Error != "" || strings.TrimSpace(step2.VerificationToken) == "" {
		return fmt.Errorf("verify code failed: %s", d.accountErr(step2.ErrorDesc, step2.Error, resp))
	}

	var out tokenResp
	resp, err = d.accountClient.R().
		SetContext(ctx).
		SetBody(map[string]any{
			"verification_code":  d.VerifyCode,
			"verification_token": step2.VerificationToken,
			"username":          normalizePhoneE164(d.PhoneNumber),
			"client_id":         d.ClientID,
		}).
		SetResult(&out).
		Post("/v1/auth/signin")
	if err != nil {
		return err
	}
	if resp.IsError() || out.Error != "" || strings.TrimSpace(out.AccessToken) == "" {
		return fmt.Errorf("signin failed: %s", d.accountErr(out.ErrorDesc, out.Error, resp))
	}

	d.AccessToken = strings.TrimSpace(out.AccessToken)
	d.RefreshToken = strings.TrimSpace(out.RefreshToken)
	d.VerificationID = ""
	d.VerifyCode = ""
	op.MustSaveDriverStorage(d)
	return nil
}

func (d *GuangYaPan) prepareSMSCode(ctx context.Context) error {
	d.VerificationID = ""
	if err := d.ensureCaptchaToken(ctx, false); err != nil {
		return err
	}
	verificationID, err := d.requestVerificationID(ctx)
	if err != nil {
		return err
	}
	d.VerificationID = verificationID
	d.SendCode = false
	op.MustSaveDriverStorage(d)
	return nil
}

func (d *GuangYaPan) requestVerificationID(ctx context.Context) (string, error) {
	if d.CaptchaToken != "" {
		d.accountClient.SetHeader("X-Captcha-Token", d.CaptchaToken)
	}

	var step1 verificationResp
	resp, err := d.accountClient.R().
		SetContext(ctx).
		SetBody(map[string]any{
			"phone_number": normalizePhoneE164(d.PhoneNumber),
			"target":       "ANY",
			"client_id":    d.ClientID,
		}).
		SetResult(&step1).
		Post("/v1/auth/verification")
	if err != nil {
		return "", err
	}
	if resp.IsError() || step1.Error != "" || strings.TrimSpace(step1.VerificationID) == "" {
		// If captcha token is expired/invalid, refresh it once and retry.
		if strings.Contains(step1.Error, "captcha_invalid") || strings.Contains(step1.ErrorDesc, "captcha_token expired") {
			if err := d.ensureCaptchaToken(ctx, true); err == nil {
				return d.requestVerificationID(ctx)
			}
		}
		return "", fmt.Errorf("request verification failed: %s", d.accountErr(step1.ErrorDesc, step1.Error, resp))
	}
	return strings.TrimSpace(step1.VerificationID), nil
}

func (d *GuangYaPan) ensureCaptchaToken(ctx context.Context, force bool) error {
	if !force && d.CaptchaToken != "" {
		d.accountClient.SetHeader("X-Captcha-Token", d.CaptchaToken)
		return nil
	}

	var out captchaInitResp
	resp, err := d.accountClient.R().
		SetContext(ctx).
		SetBody(map[string]any{
			"client_id": d.ClientID,
			"action":    "POST:/v1/auth/verification",
			"device_id": d.DeviceID,
			"meta": map[string]any{
				"username":           normalizePhoneE164(d.PhoneNumber),
				"phone_number":       normalizePhoneE164(d.PhoneNumber),
				"VERIFICATION_PHONE": normalizePhoneE164(d.PhoneNumber),
			},
		}).
		SetResult(&out).
		Post("/v1/shield/captcha/init")
	if err != nil {
		return err
	}
	if resp.IsError() || out.Error != "" || strings.TrimSpace(out.CaptchaToken) == "" {
		return fmt.Errorf("init captcha token failed: %s", d.accountErr(out.ErrorDesc, out.Error, resp))
	}
	d.CaptchaToken = strings.TrimSpace(out.CaptchaToken)
	d.accountClient.SetHeader("X-Captcha-Token", d.CaptchaToken)
	op.MustSaveDriverStorage(d)
	return nil
}

func (d *GuangYaPan) postAPI(ctx context.Context, path string, body any, result any) error {
	resp, err := d.apiClient.R().
		SetContext(ctx).
		SetHeader("Authorization", "Bearer "+d.AccessToken).
		SetBody(body).
		SetResult(result).
		Post(path)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("api request failed: status=%d body=%s", resp.StatusCode(), resp.String())
	}
	return nil
}

func (d *GuangYaPan) waitTaskDone(ctx context.Context, taskID string) error {
	for i := 0; i < 60; i++ {
		time.Sleep(1 * time.Second)
		var resp taskStatusResp
		if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/task/get_task_status", map[string]any{"taskId": taskID}, &resp); err != nil {
			return err
		}
		if resp.Data.Status == 2 {
			return nil
		}
		if resp.Data.Status == 3 {
			return errors.New("task failed")
		}
	}
	return errors.New("task timeout")
}

func (d *GuangYaPan) getUploadToken(ctx context.Context, parentID, name string, size int64) (uploadTokenData, int, error) {
	var resp uploadTokenResp
	if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/file/get_upload_token", map[string]any{
		"parentId":  parentID,
		"fileName":  name,
		"fileSize":  size,
		"dirName":   "",
		"isRewrite": false,
	}, &resp); err != nil {
		return uploadTokenData{}, 0, err
	}
	return resp.Data, resp.Code, nil
}

func (d *GuangYaPan) waitUploadTaskInfo(ctx context.Context, taskID string) error {
	for i := 0; i < 60; i++ {
		time.Sleep(1 * time.Second)
		var resp taskInfoResp
		if err := d.postAPI(ctx, "/nd.bizuserres.s/v1/task/get_task_info", map[string]any{"taskId": taskID}, &resp); err != nil {
			return err
		}
		if strings.TrimSpace(resp.Data.FileID) != "" {
			return nil
		}
	}
	return errors.New("upload task timeout")
}

func (d *GuangYaPan) multipartUploadToOSS(ctx context.Context, bucket *oss.Bucket, objectPath string, file model.FileStreamer, up driver.UpdateProgress) error {
	partSize := d.calcUploadPartSize(file.GetSize())
	f, err := os.CreateTemp("", "guangyapan-upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := io.Copy(f, file); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return bucket.UploadFile(objectPath, f.Name(), partSize, oss.Routines(3), oss.Progress(true))
}

func (d *GuangYaPan) calcUploadPartSize(fileSize int64) int64 {
	partSize := fileSize / 10
	if partSize < 1024*1024 {
		partSize = 1024 * 1024
	}
	if partSize > 1024*1024*50 {
		partSize = 1024 * 1024 * 50
	}
	return partSize
}

func (d *GuangYaPan) setTempStatus(msg string) {
	log.Infof("GuangYaPan storage [%s] temp status: %s", d.GetStorage().GetID(), msg)
}

func (d *GuangYaPan) accountErr(desc, err string, resp *resty.Response) string {
	s := strings.TrimSpace(desc)
	if s == "" {
		s = strings.TrimSpace(err)
	}
	if s == "" && resp != nil {
		s = resp.String()
	}
	if s == "" {
		s = "unknown error"
	}
	return s
}

func normalizePhoneE164(phone string) string {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	if !strings.HasPrefix(phone, "+") && !strings.HasPrefix(phone, "00") {
		phone = "+86" + phone
	}
	return phone
}

func normalizeOSSEndpoint(endpoint, bucketName string) string {
	if strings.HasPrefix(endpoint, "https://") || strings.HasPrefix(endpoint, "http://") {
		u, err := url.Parse(endpoint)
		if err == nil {
			return u.Host
		}
	}
	return endpoint
}

func normalizeDeviceID(deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	deviceID = strings.ReplaceAll(deviceID, "-", "")
	if len(deviceID) == 32 {
		return strings.ToLower(deviceID)
	}
	return ""
}

func randomDeviceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
