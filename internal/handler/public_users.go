package handler

// 公开账号资料：GET /api/users/:id（匿名可读）。
//
// 前端用户主页读的就是这条路径（frontend/src/app/users/[id]/page.tsx）。资料本身公开，
// 但 email 这类隐私字段只在请求者就是本人时带出——网关放行匿名，不代表字段也公开：
// 判定在 store.PublicProfile 里做，这里只负责把当前身份传进去（没有身份就是空串）。

import (
	"github.com/gin-gonic/gin"
)

func (h *Handler) registerPublicUsers(api *gin.RouterGroup) {
	api.GET("/users/:id", func(c *gin.Context) {
		viewer := ""
		if u := currentUser(c); u != nil {
			viewer = u.ID
		}
		p, err := h.store.PublicProfile(c.Request.Context(), c.Param("id"), viewer)
		respond(c, p, err)
	})
}
