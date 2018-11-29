package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
)

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func getGroupsInfo(r *admin.Groups, srv *admin.Service) {
	for _, u := range r.Groups {
		fmt.Printf("%s,%s,%s,%d,", u.Id, u.Name, u.Email, u.DirectMembersCount)

		// Alias 情報の展開処理
		aliascounter := 1
		fmt.Printf(`"`)
		for _, value := range u.Aliases {
			if aliascounter != len(u.Aliases) {
				fmt.Printf("%v,", value)
			} else {
				fmt.Printf("%v", value)
			}
			aliascounter++
		}
		fmt.Printf(`",`)

		// メンバーアドレスを特定します
		// m : Members 情報
		m, err := srv.Members.List(u.Id).Do()
		if err != nil {
			log.Fatalf("Unable to retrieve users in domain: %v", err)
		}

		// Do not output , at the last result
		counter := 1
		fmt.Printf(`"`)
		for _, value := range m.Members {
			if counter != len(m.Members) {
				fmt.Printf("%+v,", value.Email)
			} else {
				fmt.Printf("%+v", value.Email)
			}
			counter++
		}
		fmt.Println(`"`)
	}
}

func main() {
	b, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	// Scope 説明 : ここで OAuth2 を通して獲得したい権限を指定します
	config, err := google.ConfigFromJSON(b, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	// srv : Google SDK Client
	srv, err := admin.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve directory Client %v", err)
	}

	// Output as CSV
	fmt.Printf("ID,名前,アドレス,グループ人数,別名,メンバー\n")

	// r : Groups 情報
	// MaxResults は最大 500
	// my_customer は OAuth2 でログインした本人の身分を指します
	r, err := srv.Groups.List().Customer("my_customer").MaxResults(500).
		OrderBy("email").Do()
	if err != nil {
		log.Fatalf("Unable to retrieve group lists in domain: %v", err)
	}

	if len(r.Groups) == 0 {
		fmt.Print("No groups found.\n")
	} else {
		getGroupsInfo(r, srv)
	}

	// NextPageToken 処理
	for {
		if r.NextPageToken != "" {
			// PageToken 追加して Client に請求します
			r, err = srv.Groups.List().Customer("my_customer").MaxResults(500).PageToken(r.NextPageToken).
				OrderBy("email").Do()
			if err != nil {
				log.Fatalf("Unable to retrieve next page in the list: %v", err)
			}

			if len(r.Groups) == 0 {
				fmt.Print("Unable to retrieve next page in the list: Empty Groups returned.\n")
			} else {
				getGroupsInfo(r, srv)
			}
		} else {
			break
		}
	}
}
