package proxy

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestInspectedUploadRetainsAdmissionUntilClosed(t *testing.T) {
	var budget budget
	var tickets []*ticket
	for range 6 {
		ticket, err := budget.acquire()
		if err != nil {
			t.Fatal(err)
		}
		if err := ticket.add(8); err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
		defer ticket.release()
	}
	body := &inspectedBody{reader: io.NopCloser(strings.NewReader("buffered")), ticket: tickets[0]}
	if _, err := io.ReadAll(body); err != nil {
		t.Fatal(err)
	}
	if _, err := budget.acquire(); !errors.Is(err, errCapacity) {
		t.Fatal("upload released admission before the transport closed it")
	}
	_ = body.Close()
	_ = body.Close()
	if budget.jobs != 5 || budget.bytes != 40 || body.reader != nil {
		t.Fatal("upload close did not release exactly one reservation and its buffer")
	}
	if n, err := body.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatal("closed upload retained readable bytes")
	}
}
