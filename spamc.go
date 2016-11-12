// http://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
package spamassassin

import (
	"bufio"
	"encoding/json"
	"errors"
	"github.com/le0pard/go-falcon/config"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	spamInfoRe    = regexp.MustCompile(`(.+)\/(.+) (\d+) (.+)`)
	spamMainRe    = regexp.MustCompile(`^Spam: (.+) ; (.+) . (.+)$`)
	spamDetailsRe = regexp.MustCompile(`^(-?[0-9\.]*)\s([a-zA-Z0-9_]*)(\W*)([\w:\s-]*)`)
)

type Spamassassin struct {
	config   *config.Config
	RawEmail []byte
}

type SpamassassinHeader struct {
	Pts         string
	RuleName    string
	Description string
}

type SpamassassinResponse struct {
	ResponseCode    int
	ResponseMessage string
	Score           float64
	Spam            bool
	Threshold       float64
	Details         []SpamassassinHeader
}

// check email by spamassassin

func CheckSpamEmail(config *config.Config, email []byte) (string, error) {
	spamassassin := &Spamassassin{
		config:   config,
		RawEmail: email,
	}
	output, err := spamassassin.checkEmail()
	if err != nil {
		return "", err
	}
	response := spamassassin.parseOutput(output)
	jsonResult, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return string(jsonResult), nil
}

// check email by spamassassin

func (ss *Spamassassin) checkEmail() ([]string, error) {
	var dataArrays []string
	ip := net.ParseIP(ss.config.Spamassassin.Ip)
	if ip == nil {
		return dataArrays, errors.New("Invalid ip address")
	}
	addr := &net.TCPAddr{
		IP:   ip,
		Port: ss.config.Spamassassin.Port,
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return dataArrays, err
	}
	defer conn.Close()
	// write headers
	_, err = conn.Write([]byte("REPORT SPAMC/1.2\r\n"))
	if err != nil {
		return dataArrays, err
	}
	_, err = conn.Write([]byte("Content-length: " + strconv.Itoa(len(ss.RawEmail)) + "\r\n\r\n"))
	if err != nil {
		return dataArrays, err
	}
	// write email
	_, err = conn.Write(ss.RawEmail)
	if err != nil {
		return dataArrays, err
	}
	// force close writer
	conn.CloseWrite()
	// read data
	reader := bufio.NewReader(conn)
	// reading
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return dataArrays, err
		}
		line = strings.TrimRight(line, " \t\r\n")
		dataArrays = append(dataArrays, line)
	}

	return dataArrays, nil
}

// parse spamassassin output

func (ss *Spamassassin) parseOutput(output []string) *SpamassassinResponse {
	response := &SpamassassinResponse{}
	for _, row := range output {
		// header
		if spamInfoRe.MatchString(row) {
			res := spamInfoRe.FindStringSubmatch(row)
			if len(res) == 5 {
				resCode, err := strconv.Atoi(res[3])
				if err == nil {
					response.ResponseCode = resCode
				}
				response.ResponseMessage = res[4]
			}
		}
		// summary
		if spamMainRe.MatchString(row) {
			res := spamMainRe.FindStringSubmatch(row)
			if len(res) == 4 {
				if strings.ToLower(res[1]) == "true" || strings.ToLower(res[1]) == "yes" {
					response.Spam = true
				} else {
					response.Spam = false
				}
				resFloat, err := strconv.ParseFloat(res[2], 64)
				if err == nil {
					response.Score = resFloat
				}
				resFloat, err = strconv.ParseFloat(res[3], 64)
				if err == nil {
					response.Threshold = resFloat
				}
			}
		}
		// details
		row = strings.Trim(row, " \t\r\n")
		if spamDetailsRe.MatchString(row) {
			res := spamDetailsRe.FindStringSubmatch(row)
			if len(res) == 5 {
				header := SpamassassinHeader{Pts: res[1], RuleName: res[2], Description: res[4]}
				response.Details = append(response.Details, header)
			}
		}
	}
	return response
}
