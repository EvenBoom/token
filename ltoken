package ltoken

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

// TokenResult 验证结果
type TokenResult uint8

const (
	// TokenSuccess 校验成功
	TokenSuccess TokenResult = 1
	// TokenFailure 校验失败
	TokenFailure TokenResult = 2
	// TokenTimeOut token过期
	TokenTimeOut TokenResult = 3
)

// Token 票据对象
type Token struct {
	keys      [2]string
	timeStamp int64
}

// CreateTokenKeys 通过一个协程创建token密钥
func (token *Token) CreateTokenKeys(timeStamp int64) {
	token.timeStamp = timeStamp
	go token.keysTimer()
}

// keysTimer 每隔一段时间更换密钥
func (token *Token) keysTimer() {
	if token.keys[0] != "" {
		token.keys[1] = token.keys[0]
	}
	token.keys[0] = uuid.Must(uuid.NewV4()).String()
	timer := time.NewTimer(time.Duration(token.timeStamp))
	<-timer.C
	token.keysTimer()
}

// CreateToken 生成密钥，params为payload参数，若返回""，请返回error信息，而不是返回一个""token
func (token *Token) CreateToken(params map[string]string) (tokenStr string) {

	expStr := strconv.FormatInt(token.timeStamp, 10)
	head := `{"typ":"JWT","alg":"HS256"}`
	payload := `{"exp":"` + expStr + `"`

	for k, v := range params {
		payload = payload + `,` + `"` + k + `":"` + v + `"`
	}

	payload = payload + `}`

	if token.keys[0] == "" { //提高用户体验，防止用户得到一个key为空的token而又验证失败
		return ""
	}
	key := token.keys[0]

	headBase64 := base64.StdEncoding.EncodeToString([]byte(head))
	payloadBase64 := base64.StdEncoding.EncodeToString([]byte(payload))
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(key))

	base64Str := headBase64 + "." + payloadBase64 + "~" + keyBase64

	signatureBase64 := toSha256(base64Str)
	return headBase64 + "." + payloadBase64 + "." + signatureBase64
}

// ValidateToken 验证token
func (token *Token) ValidateToken(tokenStr string) (tokenResult TokenResult, params map[string]interface{}) {

	if tokenStr == "" {
		return TokenFailure, nil
	}

	params = tokenPayloadParams(tokenStr)

	exp, _ := strconv.ParseInt(params["exp"].(string), 10, 64)
	if exp < time.Now().Unix() {
		return TokenTimeOut, nil
	}

	for i := 0; i < 2; i++ {
		if token.keys[i] == "" { //防止系统启动过快，并且刚好有人在请求token时而产生的系统安全问题
			continue
		}
		keyBase64 := base64.StdEncoding.EncodeToString([]byte(token.keys[i]))
		base64Str := strings.Split(tokenStr, ".")[0] + "." + strings.Split(tokenStr, ".")[1] + "~" + keyBase64
		signatureBase64 := strings.Split(tokenStr, ".")[2]
		if signatureBase64 == toSha256(base64Str) {
			return TokenSuccess, params
		}
	}
	return TokenFailure, nil
}

// tokenPayloadParams 获取token参数
func tokenPayloadParams(tokenStr string) map[string]interface{} {
	splitStr := strings.Split(tokenStr, ".")[1]
	payload, _ := base64.StdEncoding.DecodeString(splitStr)
	params := make(map[string]interface{})
	json.Unmarshal(payload, &params)
	return params
}

// toSha256 sha256算法加密
func toSha256(str string) string {
	bytes := []byte(str)
	hash := sha256.Sum256(bytes)
	result := hex.EncodeToString(hash[:])
	return result
}
