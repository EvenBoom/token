package token

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

var keys [2]string
var hours int64

//通过一个协程创建token密钥
func CreateTokenKeys(hour int64) {
  	hours = hour
	go timerKeys()
}

//每隔一段时间更换密钥
func timerKeys() {
	if keys[0] == "" {
		keys[1] = uuid.Must(uuid.NewV4()).String()
	} else {
		keys[1] = keys[0]
	}
	keys[0] = uuid.Must(uuid.NewV4()).String()
	timer := time.NewTimer(time.Duration(hours) * time.Hour)
	<-timer.C
	timerKeys()
}

//生成密钥
func Token(params map[string]string) string {
  
	hour, _ := time.ParseDuration(strconv.FormatInt(hours, 10))
	sec := time.Now().Add(hour).Unix()
	expStr := strconv.FormatInt(sec, 10)
	head := `{"typ":"JWT","alg":"HS256"}`
	payload := `{"exp":"` + expStr + `",` + params + `}`
	
	for k, v := range params {
		payload = payload + `",` + `"` + k +`":"` + v +`"`
	}
	
	payload = payload + `}`
	
	key := keys[0]

	headBase64 := base64.StdEncoding.EncodeToString([]byte(head))
	payloadBase64 := base64.StdEncoding.EncodeToString([]byte(payload))
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(key))

	base64Str := headBase64 + "." + payloadBase64 + "~" + keyBase64

	signatureBase64 := toSha256(base64Str)
	return headBase64 + "." + payloadBase64 + "." + signatureBase64
}

//验证token
func ValidateToken(token string) bool {
	result := false
	if token == "" {
		return result
	}
	exp, _ := strconv.ParseInt(TokenPayloadParams(token)["exp"].(string), 10, 64)
	if exp < time.Now().Unix() {
		return result
	}

	for i := 0; i < 2; i++ {
		keyBase64 := base64.StdEncoding.EncodeToString([]byte(keys[i]))
		base64Str := strings.Split(token, ".")[0] + "." + strings.Split(token, ".")[1] + "~" + keyBase64
		signatureBase64 := strings.Split(token, ".")[2]
		if signatureBase64 == toSha256(base64Str) {
			result = true
		}
	}
	return result
}

//获取token参数
func TokenPayloadParams(token string) map[string]interface{} {
	splitStr := strings.Split(token, ".")[1]
	payload, _ := base64.StdEncoding.DecodeString(splitStr)
	params := make(map[string]interface{})
	json.Unmarshal(payload, &params)
	return params
}

//sha256算法加密
func toSha256(str string) string {
	bytes := []byte(str)
	hash := sha256.Sum256(bytes)
	result := hex.EncodeToString(hash[:])
	return result
}
