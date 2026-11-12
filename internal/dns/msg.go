package dns

import (
	"errors"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// minUDPSize is what a client without EDNS0 accepts over UDP (RFC 1035).
const minUDPSize = 512

// query is what the engine needs to know about an incoming message.
type query struct {
	header   dnsmessage.Header
	question dnsmessage.Question
	name     string // lowercase, no trailing dot
	udpSize  int    // largest UDP answer the client accepts
}

var errNotQuery = errors.New("not a standard query with one question")

func parseQuery(msg []byte) (query, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return query{}, err
	}
	if h.Response || h.OpCode != 0 {
		return query{}, errNotQuery
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return query{}, err
	}
	if len(qs) != 1 {
		return query{}, errNotQuery
	}
	q := query{header: h, question: qs[0], name: normalize(qs[0].Name.String()), udpSize: minUDPSize}
	if err := p.SkipAllAnswers(); err != nil {
		return q, nil
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return q, nil
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT && int(rh.Class) > q.udpSize {
			q.udpSize = int(rh.Class) // EDNS0 carries the UDP size in the class field
		}
		if err := p.SkipAdditional(); err != nil {
			break
		}
	}
	return q, nil
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// failure builds a SERVFAIL answer to q.
func failure(q query) []byte {
	return reply(q, dnsmessage.RCodeServerFailure, false)
}

// truncate replaces an answer that doesn't fit the client's UDP size with an
// empty one carrying the TC bit, so the client asks again over TCP.
func truncate(q query, answer []byte) []byte {
	rcode := dnsmessage.RCodeSuccess
	var p dnsmessage.Parser
	if h, err := p.Start(answer); err == nil {
		rcode = h.RCode
	}
	return reply(q, rcode, true)
}

func reply(q query, rcode dnsmessage.RCode, tc bool) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 q.header.ID,
		Response:           true,
		Truncated:          tc,
		RecursionDesired:   q.header.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q.question); err != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// answers reports whether msg is a response with the given ID.
func answers(msg []byte, id uint16) bool {
	return len(msg) >= 12 && uint16(msg[0])<<8|uint16(msg[1]) == id && msg[2]&0x80 != 0
}

func truncated(msg []byte) bool { return len(msg) >= 12 && msg[2]&0x02 != 0 }

func setID(msg []byte, id uint16) {
	msg[0], msg[1] = byte(id>>8), byte(id)
}
