package audit

import (
	"testing"
	"time"
)

func paginatorSecrets(n int) []Secret {
	secrets := make([]Secret, n)
	for i := range secrets {
		secrets[i] = Secret{Path: "secret/item", Key: "k", CreatedAt: time.Now()}
	}
	return secrets
}

func TestPaginate_InvalidPage(t *testing.T) {
	_, err := Paginate(paginatorSecrets(5), 0, 2)
	if err != ErrInvalidPage {
		t.Errorf("expected ErrInvalidPage, got %v", err)
	}
}

func TestPaginate_InvalidPageSize(t *testing.T) {
	_, err := Paginate(paginatorSecrets(5), 1, 0)
	if err != ErrInvalidPage {
		t.Errorf("expected ErrInvalidPage, got %v", err)
	}
}

func TestPaginate_FirstPage(t *testing.T) {
	p, err := Paginate(paginatorSecrets(10), 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Secrets) != 3 {
		t.Errorf("expected 3 secrets, got %d", len(p.Secrets))
	}
	if p.HasNext != true || p.HasPrev != false {
		t.Errorf("unexpected HasNext/HasPrev: %v/%v", p.HasNext, p.HasPrev)
	}
}

func TestPaginate_LastPage(t *testing.T) {
	p, err := Paginate(paginatorSecrets(10), 4, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Secrets) != 1 {
		t.Errorf("expected 1 secret on last page, got %d", len(p.Secrets))
	}
	if p.HasNext != false || p.HasPrev != true {
		t.Errorf("unexpected HasNext/HasPrev: %v/%v", p.HasNext, p.HasPrev)
	}
}

func TestPaginate_BeyondEnd(t *testing.T) {
	p, err := Paginate(paginatorSecrets(5), 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(p.Secrets))
	}
}

func TestPaginate_TotalPages(t *testing.T) {
	p, err := Paginate(paginatorSecrets(7), 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalPages != 3 {
		t.Errorf("expected 3 total pages, got %d", p.TotalPages)
	}
	if p.TotalCount != 7 {
		t.Errorf("expected total count 7, got %d", p.TotalCount)
	}
}

func TestPaginate_Empty(t *testing.T) {
	p, err := Paginate([]Secret{}, 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalPages != 1 {
		t.Errorf("expected 1 total page for empty input, got %d", p.TotalPages)
	}
}
