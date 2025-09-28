package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/pocketbase/pocketbase/tools/types"
	"golang.org/x/oauth2"
)

func init() {
	Providers[NameNextcloud] = wrapFactory(NewNextcloudProvider)
}

var _ Provider = (*Nextcloud)(nil)

// NameNextcloud is the unique name of the Nextcloud provider.
const NameNextcloud string = "nextcloud"

// Nextcloud allows authentication via Nextcloud OAuth2.
type Nextcloud struct {
	BaseProvider
}

// NewNextcloudProvider creates new Nextcloud provider instance with some defaults.
func NewNextcloudProvider() *Nextcloud {
	return &Nextcloud{BaseProvider{
		ctx:         context.Background(),
		displayName: "Nextcloud",
		pkce:        true,
		scopes:      []string{"read:user", "user:email"},
		authURL:     "https://nextcloud.your.domain/apps/oauth2/authorize",
		tokenURL:    "https://nextcloud.your.domain/apps/oauth2/api/v1/token",
		userInfoURL: "https://nextcloud.your.domain/ocs/v2.php/cloud/user?format=json",
	}}
}

// FetchAuthUser returns an AuthUser instance based on Nextcloud's user api.
//
// API reference: https://nextcloud.com/api/v1/user
func (p *Nextcloud) FetchAuthUser(token *oauth2.Token) (*AuthUser, error) {
	slog.Debug("Nextcloud user data fetched", "data", token)
	data, err := p.FetchRawUserInfo(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err := json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	// Define a struct matching the Nextcloud response structure
	var resp struct {
		OCS struct {
			Data struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayname"`
				Email       string `json:"email"`
				// Add more fields if needed
			} `json:"data"`
		} `json:"ocs"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	user := &AuthUser{
		Id:           resp.OCS.Data.ID,
		Name:         resp.OCS.Data.DisplayName,
		Username:     resp.OCS.Data.ID,
		Email:        resp.OCS.Data.Email,
		AvatarURL:    "", // Nextcloud API does not provide avatar URL here
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	user.Expiry, _ = types.ParseDateTime(token.Expiry)

	return user, nil
}

// FetchRawUserInfo implements Provider.FetchRawUserInfo interface method.
//
// It either fetch the data from p.userInfoURL, or if not set - returns the id_token claims.
func (p *Nextcloud) FetchRawUserInfo(token *oauth2.Token) ([]byte, error) {
	if p.userInfoURL != "" {
		return p.BaseProvider.FetchRawUserInfo(token)
	}

	req, err := http.NewRequestWithContext(p.ctx, "GET", p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("OCS-APIRequest", "true")

	return p.sendRawUserInfoRequest(req, token)
}
