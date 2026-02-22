package utils

import "strconv"

const (
	defaultLimit      = 20
	defaultPageNumber = 0
)

// Pagination holds computed skip and limit values for MongoDB queries.
type Pagination struct {
	Limit      int64
	Skip       int64
	PageNumber int64
}

// ParsePagination parses limit and pageNumber query params with safe defaults.
func ParsePagination(limitStr, pageStr string) Pagination {
	limit := parseInt64(limitStr, defaultLimit)
	page := parseInt64(pageStr, defaultPageNumber)

	if limit <= 0 || limit > 100 {
		limit = defaultLimit
	}
	if page < 0 {
		page = 0
	}

	return Pagination{
		Limit:      limit,
		Skip:       page * limit,
		PageNumber: page,
	}
}

func parseInt64(s string, fallback int64) int64 {
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}
