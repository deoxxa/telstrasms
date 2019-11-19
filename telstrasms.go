package telstrasms

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	baseURL  = "https://tapi.telstra.com/v2/messages"
	tokenURL = "https://tapi.telstra.com/v2/oauth/token"
)

type Client struct {
	cfg    *clientcredentials.Config
	hc     *http.Client
	l      sync.RWMutex
	token  string
	expiry time.Time
}

func New(clientID, clientSecret string) *Client {
	return &Client{
		cfg: &clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
		},
		hc: &http.Client{Transport: http.DefaultTransport},
	}
}

func (c *Client) ensureToken(ctx context.Context, t time.Time) error {
	c.l.RLock()
	if c.token != "" && c.expiry.After(t) {
		c.l.RUnlock()
		return nil
	}
	c.l.RUnlock()

	c.l.Lock()
	if c.token != "" && c.expiry.After(t) {
		c.l.Unlock()
		return nil
	}
	defer c.l.Unlock()

	tk, err := c.cfg.Token(context.WithValue(ctx, oauth2.HTTPClient, c.hc))
	if err != nil {
		return errors.Wrap(err, "telstrasms.Client.ensureToken: couldn't get token")
	}

	c.token = tk.AccessToken
	c.expiry = tk.Expiry

	return nil
}

func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.ensureToken(ctx, time.Now()); err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.do: couldn't ensure token")
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	res, err := c.hc.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.do: couldn't perform request")
	}

	return res, nil
}

type Subscription struct {
	DestinationAddress string `json:"destinationAddress"`
	ExpiryDate         int64  `json:"expiryDate"`
}

type CreateSubscriptionInput struct {
	ActiveDays int    `json:"activeDays,omitempty"`
	NotifyURL  string `json:"notifyURL"`
}

func (c *Client) CreateSubscription(ctx context.Context, input CreateSubscriptionInput) (*Subscription, error) {
	d, err := json.Marshal(input)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't serialise input")
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/provisioning/subscriptions", bytes.NewReader(d))
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't construct request")
	}
	req.Header.Set("content-type", "application/json")

	res, err := c.do(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't perform request")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusNoContent {
		d, _ := ioutil.ReadAll(res.Body)
		return nil, errors.Errorf("telstrasms.Client.CreateSubscription: invalid status; expected 200 OK but got %s: %q", res.Status, string(d))
	}

	if res.StatusCode == http.StatusNoContent {
		v, err := c.GetSubscription(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription")
		}

		return v, nil
	}

	var v Subscription
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't decode response")
	}

	return &v, nil
}

func (c *Client) GetSubscription(ctx context.Context) (*Subscription, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/provisioning/subscriptions", nil)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.GetSubscription: couldn't construct request")
	}
	req.Header.Set("content-type", "application/json")

	res, err := c.do(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.GetSubscription: couldn't perform request")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			return nil, nil
		}

		d, _ := ioutil.ReadAll(res.Body)
		return nil, errors.Errorf("telstrasms.Client.GetSubscription: invalid status; expected 200 OK but got %s: %q", res.Status, string(d))
	}

	var v Subscription
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.GetSubscription: couldn't decode response")
	}

	return &v, nil
}

func (c *Client) EnsureSubscription(ctx context.Context, input CreateSubscriptionInput) (*Subscription, error) {
	s, err := c.GetSubscription(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.EnsureSubscription")
	}

	if s != nil {
		return s, nil
	}

	s, err = c.CreateSubscription(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.EnsureSubscription")
	}

	if s != nil {
		return s, nil
	}

	return nil, nil
}

type Message struct {
	To               string `json:"string"`
	DeliveryStatus   string `json:"deliveryStatus"`
	MessageID        string `json:"messageId"`
	MessageStatusURL string `json:"messageStatusURL"`
}

type SendSMSInput struct {
	To                         string `json:"to"`
	Body                       string `json:"body"`
	From                       string `json:"from,omitempty"`
	ValidityInMinutes          int    `json:"validity,omitempty"`
	ScheduledDeliveryInMinutes int    `json:"scheduleDelivery,omitempty"`
	NotifyURL                  string `json:"notifyURL,omitempty"`
	ReplyRequest               bool   `json:"replyRequest,omitempty"`
	Priority                   bool   `json:"priority,omitempty"`
}

type SendSMSResponse struct {
	MessageType      string    `json:"messageType"`
	NumberOfSegments int       `json:"numberSegments"`
	Messages         []Message `json:"messages"`
}

func (c *Client) SendSMS(ctx context.Context, input SendSMSInput) (*Subscription, error) {
	d, err := json.Marshal(input)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't serialise input")
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/sms", bytes.NewReader(d))
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't construct request")
	}
	req.Header.Set("content-type", "application/json")

	res, err := c.do(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't perform request")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		d, _ := ioutil.ReadAll(res.Body)
		return nil, errors.Errorf("telstrasms.Client.CreateSubscription: invalid status; expected 201 Created but got %s: %q", res.Status, string(d))
	}

	var v Subscription
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.CreateSubscription: couldn't decode response")
	}

	return &v, nil
}

type SMS struct {
	Status             string    `json:"status"`
	DestinationAddress string    `json:"destinationAddress"`
	SenderAddress      string    `json:"senderAddress"`
	Message            string    `json:"message"`
	MessageID          string    `json:"messageId"`
	SentTimestamp      time.Time `json:"sentTimestamp"`
}

func (c *Client) GetSMS(ctx context.Context) (*SMS, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/sms", nil)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.GetSMS: couldn't construct request")
	}
	req.Header.Set("content-type", "application/json")

	res, err := c.do(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "telstrasms.Client.GetSMS: couldn't perform request")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		d, _ := ioutil.ReadAll(res.Body)
		return nil, errors.Errorf("telstrasms.Client.GetSMS: invalid status; expected 200 OK but got %s: %q", res.Status, string(d))
	}

	d, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Errorf("telstrasms.Client.GetSMS: couldn't read body")
	}

	var v SMS
	if err := json.Unmarshal(d, &v); err != nil {
		return nil, errors.Wrapf(err, "telstrasms.Client.GetSMS: couldn't decode response: %s", string(d))
	}

	if v.DestinationAddress == "" || v.Message == "" {
		return nil, nil
	}

	return &v, nil
}
