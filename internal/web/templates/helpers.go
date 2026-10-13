package templates

import (
	"strconv"

	"github.com/rom/otinv/internal/model"
)

func roleName(s string) model.RoleName { return model.RoleName(s) }

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func vlanLabel(v *uint16) string {
	if v == nil {
		return "—"
	}
	return strconv.Itoa(int(*v))
}

func pageLabel(v AssetsView) string {
	page, pages := v.PageInfo()
	return strconv.Itoa(page) + " / " + strconv.Itoa(pages)
}
