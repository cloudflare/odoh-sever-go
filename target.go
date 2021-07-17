// The MIT License
//
// Copyright (c) 2019-2020, Cloudflare, Inc. and Apple, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

type targetServer struct {
	verbose            bool
	resolver           []resolver
	odohKeyPair        odoh.ObliviousDoHKeyPair
	telemetryClient    *telemetry
	serverInstanceName string
	experimentId       string
}

const (
	dnsMessageContentType  = "application/dns-message"
	odohMessageContentType = "application/oblivious-dns-message"
)

func decodeDNSQuestion(encodedMessage []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(encodedMessage)
	return msg, err
}

func (s *targetServer) parseQueryFromRequest(r *http.Request) (*dns.Msg, error) {
	switch r.Method {
	case http.MethodGet:
		var queryBody string
		if queryBody = r.URL.Query().Get("dns"); queryBody == "" {
			return nil, fmt.Errorf("Missing DNS query parameter in GET request")
		}

		encodedMessage, err := base64.RawURLEncoding.DecodeString(queryBody)
		if err != nil {
			return nil, err
		}

		return decodeDNSQuestion(encodedMessage)
	case http.MethodPost:
		if r.Header.Get("Content-Type") != dnsMessageContentType {
			return nil, fmt.Errorf("incorrect content type, expected '%s', got %s", dnsMessageContentType, r.Header.Get("Content-Type"))
		}

		defer r.Body.Close()
		encodedMessage, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}

		return decodeDNSQuestion(encodedMessage)
	default:
		return nil, fmt.Errorf("unsupported HTTP method")
	}
}

func (s *targetServer) resolveQueryWithResolver(q *dns.Msg, r resolver) ([]byte, error) {
	packedQuery, err := q.Pack()
	if err != nil {
		log.Println("Failed encoding DNS query:", err)
		return nil, err
	}

	if s.verbose {
		log.Printf("Query=%s\n", packedQuery)
	}

	start := time.Now()
	response, err := r.resolve(q)
	if err != nil {
		log.Println("Resolution failed: ", err)
		return nil, err
	}
	elapsed := time.Since(start)

	packedResponse, err := response.Pack()
	if err != nil {
		log.Println("Failed encoding DNS response:", err)
		return nil, err
	}

	if s.verbose {
		log.Printf("Answer=%s elapsed=%s\n", packedResponse, elapsed.String())
	}

	return packedResponse, err
}

func (s *targetServer) dohQueryHandler(w http.ResponseWriter, r *http.Request) {
	requestReceivedTime := time.Now()
	exp := experiment{}
	exp.ExperimentID = s.experimentId
	exp.IngestedFrom = s.serverInstanceName
	exp.ProtocolType = "ClearText-ODOH"
	exp.RequestID = nil
	timestamp := runningTime{}

	timestamp.Start = requestReceivedTime.UnixNano()
	query, err := s.parseQueryFromRequest(r)
	if err != nil {
		log.Println("Failed parsing request:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	timestamp.TargetQueryDecryptionTime = time.Now().UnixNano()

	availableResolvers := len(s.resolver)
	chosenResolver := rand.Intn(availableResolvers)
	packedResponse, err := s.resolveQueryWithResolver(query, s.resolver[chosenResolver])
	if err != nil {
		log.Println("Failed resolving DNS query:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	endTime := time.Now().UnixNano()
	timestamp.TargetQueryResolutionTime = endTime
	timestamp.TargetAnswerEncryptionTime = endTime
	timestamp.EndTime = endTime

	exp.Timestamp = timestamp
	exp.Resolver = s.resolver[chosenResolver].name()
	exp.Status = true

	if s.telemetryClient.logClient != nil {
		go s.telemetryClient.streamTelemetryToGCPLogging([]string{exp.serialize()})
	} else if s.telemetryClient.esClient != nil {
		go s.telemetryClient.streamDataToElastic([]string{exp.serialize()})
	}

	w.Header().Set("Content-Type", dnsMessageContentType)
	w.Write(packedResponse)
}

func (s *targetServer) parseObliviousQueryFromRequest(r *http.Request) (odoh.ObliviousDNSMessage, error) {
	if r.Method != http.MethodPost {
		return odoh.ObliviousDNSMessage{}, fmt.Errorf("Unsupported HTTP method for Oblivious DNS query: %s", r.Method)
	}

	defer r.Body.Close()
	encryptedMessageBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	return odoh.UnmarshalDNSMessage(encryptedMessageBytes)
}

func (s *targetServer) createObliviousResponseForQuery(context odoh.ResponseContext, dnsResponse []byte) (odoh.ObliviousDNSMessage, error) {
	response := odoh.CreateObliviousDNSResponse(dnsResponse, 0)
	odohResponse, err := context.EncryptResponse(response)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	if s.verbose {
		log.Printf("Encrypted response: %x", odohResponse)
	}

	return odohResponse, err
}

func (s *targetServer) odohQueryHandler(w http.ResponseWriter, r *http.Request) {
	requestReceivedTime := time.Now()
	exp := experiment{}
	exp.ExperimentID = s.experimentId
	exp.IngestedFrom = s.serverInstanceName
	exp.ProtocolType = "ODOH"
	timestamp := runningTime{}

	timestamp.Start = requestReceivedTime.UnixNano()
	odohMessage, err := s.parseObliviousQueryFromRequest(r)
	if err != nil {
		log.Println("parseObliviousQueryFromRequest failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	keyID := s.odohKeyPair.Config.Contents.KeyID()
	receivedKeyID := odohMessage.KeyID
	if !bytes.Equal(keyID, receivedKeyID) {
		log.Println("received keyID is different from expected key ID")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}

	obliviousQuery, responseContext, err := s.odohKeyPair.DecryptQuery(odohMessage)
	if err != nil {
		log.Println("DecryptQuery failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	query, err := decodeDNSQuestion(obliviousQuery.Message())
	if err != nil {
		log.Println("decodeDNSQuestion failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	queryParseAndDecryptionCompleteTime := time.Now().UnixNano()
	timestamp.TargetQueryDecryptionTime = queryParseAndDecryptionCompleteTime

	chosenResolver := rand.Intn(len(s.resolver))
	packedResponse, err := s.resolveQueryWithResolver(query, s.resolver[chosenResolver])
	if err != nil {
		log.Println("resolveQueryWithResolver failed:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	queryResolutionCompleteTime := time.Now().UnixNano()
	timestamp.TargetQueryResolutionTime = queryResolutionCompleteTime

	obliviousResponse, err := s.createObliviousResponseForQuery(responseContext, packedResponse)
	if err != nil {
		log.Println("createObliviousResponseForQuery failed:", err)
		timestamp.TargetAnswerEncryptionTime = 0
		timestamp.EndTime = 0
		exp.Timestamp = timestamp
		exp.Status = false
		exp.Resolver = ""
		if s.telemetryClient.logClient != nil {
			go s.telemetryClient.streamTelemetryToGCPLogging([]string{exp.serialize()})
		} else if s.telemetryClient.esClient != nil {
			go s.telemetryClient.streamDataToElastic([]string{exp.serialize()})
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	packedResponseMessage := obliviousResponse.Marshal()

	answerEncryptionAndSerializeCompletionTime := time.Now().UnixNano()
	timestamp.TargetAnswerEncryptionTime = answerEncryptionAndSerializeCompletionTime

	if s.verbose {
		log.Printf("Target response: %x", packedResponseMessage)
	}

	returnResponseTime := time.Now().UnixNano()
	timestamp.EndTime = returnResponseTime

	exp.Timestamp = timestamp
	exp.Resolver = s.resolver[chosenResolver].name()
	exp.Status = true

	if s.telemetryClient.logClient != nil {
		go s.telemetryClient.streamTelemetryToGCPLogging([]string{exp.serialize()})
	} else if s.telemetryClient.esClient != nil {
		go s.telemetryClient.streamDataToElastic([]string{exp.serialize()})
	}

	w.Header().Set("Content-Type", odohMessageContentType)
	w.Write(packedResponseMessage)
}

func (s *targetServer) targetQueryHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	if r.Header.Get("Content-Type") == dnsMessageContentType {
		s.dohQueryHandler(w, r)
	} else if r.Header.Get("Content-Type") == odohMessageContentType {
		s.odohQueryHandler(w, r)
	} else {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

func (s *targetServer) configHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)

	configSet := []odoh.ObliviousDoHConfig{s.odohKeyPair.Config}
	configs := odoh.CreateObliviousDoHConfigs(configSet)
	w.Write(configs.Marshal())
}
