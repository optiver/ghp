package gitcache

import (
	"fmt"
	"net/url"
	"sync"

	"github.com/goodtune/ghp/internal/egress"
)

// Registry manages the set of cached ManagedRepository instances, keyed
// by owner/repo. It lazily initialises repositories on first access.
type Registry struct {
	egress         *egress.Pool
	storageFactory CacheStorageFactory
	baseURL        *url.URL // upstream GitHub URL (e.g. https://github.com)

	mu    sync.Mutex
	repos map[string]*ManagedRepository // key: "owner/repo"
}

// NewRegistry creates a Registry that uses the given storage factory and
// upstream base URL.
func NewRegistry(factory CacheStorageFactory, baseURL *url.URL) *Registry {
	return &Registry{
		storageFactory: factory,
		baseURL:        baseURL,
		repos:          make(map[string]*ManagedRepository),
	}
}

// SetEgressPool sets the proxy pool before the registry is used.
func (r *Registry) SetEgressPool(pool *egress.Pool) { r.egress = pool }

// Get returns the ManagedRepository for the given owner/repo, creating
// and initialising it if it doesn't exist yet (lazy population).
func (r *Registry) Get(owner, repo string) (*ManagedRepository, error) {
	key := owner + "/" + repo

	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.repos[key]; ok {
		return m, nil
	}

	store, err := r.storageFactory.Open(owner, repo)
	if err != nil {
		return nil, fmt.Errorf("open storage for %s: %w", key, err)
	}

	upstream := *r.baseURL
	upstream.Path = "/" + owner + "/" + repo + ".git"

	m, err := openManagedRepository(owner, repo, &upstream, store)
	if err != nil {
		return nil, fmt.Errorf("open managed repo %s: %w", key, err)
	}

	m.egress = r.egress
	r.repos[key] = m
	return m, nil
}

// Remove removes a cached repository from the registry and deletes its
// backing storage.
func (r *Registry) Remove(owner, repo string) error {
	key := owner + "/" + repo

	r.mu.Lock()
	delete(r.repos, key)
	r.mu.Unlock()

	return r.storageFactory.Delete(owner, repo)
}
