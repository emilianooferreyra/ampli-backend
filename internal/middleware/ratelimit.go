package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// ipLimiter holds a rate limiter per IP.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// store is a thread-safe map of IP → limiter.
type store struct {
	mu       sync.Mutex
	limiters map[string]*ipLimiter
	r        rate.Limit
	b        int
}

func newStore(r rate.Limit, b int) *store {
	s := &store{
		limiters: make(map[string]*ipLimiter),
		r:        r,
		b:        b,
	}
	go s.cleanup()
	return s
}

func (s *store) getLimiter(ip string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	if v, ok := s.limiters[ip]; ok {
		v.lastSeen = time.Now()
		return v.limiter
	}

	l := &ipLimiter{
		limiter:  rate.NewLimiter(s.r, s.b),
		lastSeen: time.Now(),
	}
	s.limiters[ip] = l
	return l.limiter
}

// cleanup removes stale entries every 10 minutes.
func (s *store) cleanup() {
	for {
		time.Sleep(10 * time.Minute)
		s.mu.Lock()
		for ip, v := range s.limiters {
			if time.Since(v.lastSeen) > 15*time.Minute {
				delete(s.limiters, ip)
			}
		}
		s.mu.Unlock()
	}
}

func rateLimitMiddleware(r rate.Limit, b int) gin.HandlerFunc {
	s := newStore(r, b)
	return func(c *gin.Context) {
		if !s.getLimiter(c.ClientIP()).Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests from this IP, please try again later.",
			})
			return
		}
		c.Next()
	}
}

// GlobalRateLimit mirrors the global limiter: 100 req / 15 min per IP.
func GlobalRateLimit() gin.HandlerFunc {
	// 100 requests per 15 minutes = ~0.111 req/sec burst of 100
	return rateLimitMiddleware(rate.Every(15*time.Minute/100), 100)
}

// AuthRateLimit is stricter for auth endpoints.
func AuthRateLimit() gin.HandlerFunc {
	// 10 requests per 15 minutes
	return rateLimitMiddleware(rate.Every(15*time.Minute/10), 10)
}

// UploadRateLimit limits upload endpoints.
func UploadRateLimit() gin.HandlerFunc {
	// 20 requests per hour
	return rateLimitMiddleware(rate.Every(time.Hour/20), 20)
}

// PasswordResetRateLimit is very strict for password reset.
func PasswordResetRateLimit() gin.HandlerFunc {
	// 5 requests per 15 minutes
	return rateLimitMiddleware(rate.Every(15*time.Minute/5), 5)
}
