package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net"
	"net/http"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
)

type captchaToken struct {
	Answer string    `json:"answer"`
	Host   string    `json:"host"`
	Until  time.Time `json:"until"`
	Nonce  string    `json:"nonce"`
}

func (a *API) loginCaptchaEnabled(r *http.Request) bool {
	var security struct {
		Enabled bool `json:"login_captcha"`
	}
	return a.Store.Setting(r.Context(), "security", &security) == nil && security.Enabled
}
func (a *API) captcha(w http.ResponseWriter, r *http.Request) {
	digits := make([]byte, 5)
	if _, err := rand.Read(digits); err != nil {
		a.internal(w, r, err)
		return
	}
	for i := range digits {
		digits[i] = '0' + digits[i]%10
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	nonce, err := cryptobox.RandomHex(16)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	raw, _ := json.Marshal(captchaToken{string(digits), host, time.Now().UTC().Add(3 * time.Minute), nonce})
	token, err := a.Store.Box.Seal("login-captcha", raw)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	img := image.NewRGBA(image.Rect(0, 0, 180, 56))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{242, 243, 244, 255}}, image.Point{}, draw.Src)
	// Seven segment glyphs are rendered as pixels; the response contains no answer text.
	segments := [][4]int{{0, 0, 18, 3}, {16, 0, 19, 20}, {16, 18, 19, 38}, {0, 35, 18, 38}, {0, 18, 3, 38}, {0, 0, 3, 20}, {0, 17, 18, 20}}
	masks := []byte{63, 6, 91, 79, 102, 109, 125, 7, 127, 111}
	for i, d := range digits {
		x, y := 14+i*33, 8+int(digits[(i+1)%5]%5)
		for n, s := range segments {
			if masks[d-'0']&(1<<n) != 0 {
				rect := image.Rect(x+s[0], y+s[1], x+s[2], y+s[3])
				draw.Draw(img, rect, &image.Uniform{color.RGBA{55, 65, 81, 255}}, image.Point{}, draw.Src)
			}
		}
	}
	noise := make([]byte, 360)
	rand.Read(noise)
	for i := 0; i < len(noise); i += 3 {
		img.Set(int(noise[i])%180, int(noise[i+1])%56, color.RGBA{140, 150, 160, 255})
	}
	var content bytes.Buffer
	if err = png.Encode(&content, img); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]any{"token": token, "image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(content.Bytes()), "expires_in": 180})
}
func (a *API) consumeCaptcha(r *http.Request, token, answer string) bool {
	raw, err := a.Store.Box.Open("login-captcha", token)
	if err != nil {
		return false
	}
	var value captchaToken
	if json.Unmarshal(raw, &value) != nil || time.Now().After(value.Until) {
		return false
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if value.Host != host || subtle.ConstantTimeCompare([]byte(value.Answer), []byte(answer)) != 1 {
		return false
	}
	id := "captcha_used:" + cryptobox.Hash(value.Nonce)
	enc, err := a.Store.Encrypt("setting:"+id, map[string]any{"expires_at": value.Until})
	if err != nil {
		return false
	}
	result, err := a.Store.DB.ExecContext(r.Context(), "INSERT IGNORE INTO settings(name,ciphertext,updated_at) VALUES(?,?,UTC_TIMESTAMP(6))", id, enc)
	if err != nil {
		return false
	}
	n, err := result.RowsAffected()
	return err == nil && n == 1
}
