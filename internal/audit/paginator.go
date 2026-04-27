package audit

import "errors"

// ErrInvalidPage is returned when page or page size parameters are invalid.
var ErrInvalidPage = errors.New("page and page_size must be greater than zero")

// Page holds a single page of secrets along with pagination metadata.
type Page struct {
	Secrets    []Secret
	Page       int
	PageSize   int
	TotalCount int
	TotalPages int
	HasNext    bool
	HasPrev    bool
}

// Paginate slices secrets into pages and returns the requested page.
func Paginate(secrets []Secret, page, pageSize int) (Page, error) {
	if page < 1 || pageSize < 1 {
		return Page{}, ErrInvalidPage
	}

	total := len(secrets)
	totalPages := total / pageSize
	if total%pageSize != 0 {
		totalPages++
	}
	if totalPages == 0 {
		totalPages = 1
	}

	start := (page - 1) * pageSize
	if start >= total {
		return Page{
			Secrets:    []Secret{},
			Page:       page,
			PageSize:   pageSize,
			TotalCount: total,
			TotalPages: totalPages,
			HasNext:    false,
			HasPrev:    page > 1,
		}, nil
	}

	end := start + pageSize
	if end > total {
		end = total
	}

	return Page{
		Secrets:    secrets[start:end],
		Page:       page,
		PageSize:   pageSize,
		TotalCount: total,
		TotalPages: totalPages,
		HasNext:    end < total,
		HasPrev:    page > 1,
	}, nil
}
