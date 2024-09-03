package credentials

import (
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go/v4"
)

const SampleKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwCPdYprMz3AMh4CwK8fPdArUL63RMVYoXXYfzFdluW5XYE5m\n0a5PuNpMoc33i7+JYGOCS1T+ZhoAM2AHO3/BbC2sB5qNNj48ToR7RADgy+pKyaUa\niks4hWXI2fqzAZR11xFEMkCKl0S7Zn4t/oZkFlXbgI+fxt+ab8+9rXa770pL7yCO\nlh5HLIQ1VUPWJN7JeBiKfSnBowGLuelQ8ot7YJmEhohBUN++5ZrfSqPedeLlDYPV\nZLYlEaZE6Xtg0lI+prsJ6wiv0IlTwH7yYECc2XE8MjyWAlNEoObK6kbfD0oIQqU1\noSXkRCp21MHoJ9ZTFJvd+2GArbYTzz0KL/r7TQIDAQABAoIBAQCfXmAnhIyy1pad\n4gC+H5qT/tNmxL6KNJOAihTv8eH/P2WcDQu9id64TeFYKDXWpUU2PPN6toHYgGKA\nOntlP59Ysj1JhUjxoAd3fO2dRzkuCiSEQrzTznaQNw+0tfu6KMDhZYHySJRryefC\nqJBP2Hq2B/rsFLULSLaZXW9PrPdPDxijnq+Mnok8t+1F1LRkhdXAiTAAryLT7V4I\neK6uMd0bHK776dQy7A0hR55B5NOW/1U5iYHhNMNCw31Tct9Ula5Dt5U+oe69xMd5\ntog7UaESglsovusN65GpXjwsBUN/a4qYXXUEa3ZWhDsuH3b2ekcMRgfsx5QLSDqH\n5nFtX3kFAoGBAPLa4oBmLerzZ68GMU+uKQscN/C8o671UTS7jCbtWcBMUZOGrN3q\n+smpB0YB9W4kALSxYM4LsTQ4n8qkfJz1vlMu6iATcPnG+KlEhVITUHXB/ek5aWfZ\nN1uZDGUlg0sgWSlubnNs5xl6J8tYGRrk84g5i6QCSYxesoJ+M/1P7yozAoGBAMqK\nP/PYkbJWq/gh3KcrbbiQhjz6EoPlypcjBzdfQnPamJ94voh2YYNETlDXTSr5bATP\n+dooSaw6lkoDIzZg9IZrq9FDOwXjHptpakpIkYKXKxLVcBl6PrD/hv7jznawdLrP\nyWr9nkqIVHvJxMGvjg7ONgJhCuCHmecrO50p4sR/AoGAa/8aqq7FzK3hddvzIdP5\nPI+X8N5yi+Nb8W9VrBnwx6sou8owJZ/RVsxsB53nXstz5ObcfcSFUQu9Q4hSQhqm\nQKekRg9fNjRdcCiggRdFuJhEKer2DNBz5a/x6yj7cfU4sUwCoiHTw2inOa47u9IE\n2pd8mbrKqjmSeKVWyVc6rDECgYAlrp0BYByTQn7SNnKYA4NxYCopdBk3wuvzPIge\nLDHv3g6hNNS2DNhNlMrBTZ1EzozjRFJm3TH/whKuCHFnr5gu3h9kWo7DpKLQJUeq\nNGAmHLvd0CoAA3dgdNoH2BhUirXc/8WoizEFCuI0+bAKnP/gD0uLG8TrSy8+DBQW\nRHG1PwKBgBAsnnjH4KplKrzfMycTczHEM1pll/wWBe38TbA7YjrOYLGJkac0UVVQ\nGqhoj3JfpSlWoUbMrOlyY7FlIptmj71P+xPNThKTcc42KMzYJCPhdMllXWktwWKo\nhQZsXUbv/2dzOsyQZWcWM/k+kVArS4+Q3eStBNxaDl0aNQC9CUUg\n-----END RSA PRIVATE KEY-----"



func mockJWTRetriveReader(creds JwtCredentials) io.Reader {
	form := url.Values{}
	form.Add("grant_type", string(jwtGrantType))


	return strings.NewReader(form.Encode())
}

func Test_jwtProvider_Retrieve(t *testing.T) {

	pemData := []byte(SampleKey)

	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(pemData)

	type fields struct {
		creds          JwtCredentials
		expirationTime int64
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "Token Retriever w/ Time 1",
			fields: fields{
				creds: JwtCredentials{
					URL:            "http://test.password.session",
					ClientId:       "12345",
					ClientUsername: "myusername",
					ClientKey:      signKey,
				},
				expirationTime: int64(1724867175), // for 2024-08-28 10:46:15 -0700 PDT
			},
			want: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3Rlc3QucGFzc3dvcmQuc2Vzc2lvbiJdLCJleHAiOjE3MjQ4NjcxNzUsImlzcyI6IjEyMzQ1Iiwic3ViIjoibXl1c2VybmFtZSJ9.ih_K4b8z3Eb8cIA6wxbVk1r1TNhLcfXbqoBgmBdotDD1bB7crCx8fogPWv3dSMsmiPD8CRs4pb5RRdfN4bczTOG5A3hfgCOe78WilROLnT82ndYePZNAZDT5-ODVO5hgGYsz2jeHC6gPyEmau0VXzE0v8LKNZvc1siiG3NX4bSEnAmK60Pt-JXwuKm6tz7lS3KXUOxQ8Ku_1-0mrYHWQv7_r-0u37cL0D6ccMifeGYIIDYLsa1p_dU4ETHAdUlqYGvYkyA_OoadL6Tf3zpsxzFWjFsoDY4ASwRi93NhcAUpexW6xgl4L3ogMyxFng3Ggi49ptTxCsgLJIOyCWKZlUg",
			wantErr: false,
		},
		{
			name: "Token Retriever w/ Time 2",
			fields: fields{
				creds: JwtCredentials{
					URL:            "http://test.password.session",
					ClientId:       "12345",
					ClientUsername: "myusername",
					ClientKey:      signKey,
				},
				expirationTime: int64(1724867449), // for 2024-08-28 10:50:49 -0700 PDT
			},
			want: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3Rlc3QucGFzc3dvcmQuc2Vzc2lvbiJdLCJleHAiOjE3MjQ4Njc0NDksImlzcyI6IjEyMzQ1Iiwic3ViIjoibXl1c2VybmFtZSJ9.sGgac60nELTuSPgtnb1yLla094TAtg_uI5FJJ0qObl0ETs_fdAVcyUtlTJKWIBlTIbogM-eOFHqTo7b68Ug1JcC0yWpQ88iEwbmHJcVx4DVT1D50zIZ7ljKRjfaM95LMdcI8g-102dfJ54SmhXU5pv9xucDfjL4CzeTWiWab3rht_X8UH7Sa0fSOP5lnC5bbMPsfPlMCObg0UYJW1s8ytV3w-mgdGQeJWPYJbTFLPiwUQtuwOtoD3yC9w9GDiwlnrDO0aoB8PrhUwsOrqUuRau8zl4MJeehYgvqGx6X1toKAwnsvsDM40OR_LQ31SIH8aLJQqSW_hMEGBgR6f07fhg",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &jwtProvider{
				creds: tt.fields.creds,
			}
			token, err := provider.BuildClaimsToken(tt.fields.expirationTime, provider.creds.URL, provider.creds.ClientId, provider.creds.ClientUsername)

			if err != nil && !tt.wantErr {
				t.Error()
			}

			if token != tt.want {
				t.Error("tokens do not match")
			}
		})
	}
}
