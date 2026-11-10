package desktop

import (
	"context"

	"kill-switch/internal/ui"
)

func (s *Service) Packages() ([]ui.Package, error) {
	return s.client.PackagesAsync(context.Background())
}
