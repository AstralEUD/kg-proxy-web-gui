package handlers

import (
	"kg-proxy-web-gui/backend/models"

	"github.com/gofiber/fiber/v2"
)

// GetSignatures - Get all attack signatures
func (h *Handler) GetSignatures(c *fiber.Ctx) error {
	var signatures []models.AttackSignature
	if err := h.DB.Order("category, name").Find(&signatures).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "시그니처 목록 조회 실패"})
	}
	return c.JSON(signatures)
}

// CreateSignature - Create a new attack signature
func (h *Handler) CreateSignature(c *fiber.Ctx) error {
	var sig models.AttackSignature
	if err := c.BodyParser(&sig); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "잘못된 요청 형식"})
	}

	// Validate required fields
	if sig.Name == "" || sig.Protocol == "" || sig.Category == "" {
		return c.Status(400).JSON(fiber.Map{"error": "이름, 프로토콜, 카테고리는 필수입니다"})
	}

	// Check if name already exists
	var existing models.AttackSignature
	if h.DB.Where("name = ?", sig.Name).First(&existing).Error == nil {
		return c.Status(409).JSON(fiber.Map{"error": "이미 존재하는 시그니처 이름입니다"})
	}

	sig.IsBuiltin = false // User-created signatures are not builtin
	if err := h.DB.Create(&sig).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "시그니처 생성 실패"})
	}

	return c.Status(201).JSON(sig)
}

// UpdateSignature - Update an attack signature
func (h *Handler) UpdateSignature(c *fiber.Ctx) error {
	id := c.Params("id")

	var existing models.AttackSignature
	if err := h.DB.First(&existing, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "시그니처를 찾을 수 없습니다"})
	}

	var update models.AttackSignature
	if err := c.BodyParser(&update); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "잘못된 요청 형식"})
	}

	// Builtin signatures can only toggle enabled status
	if existing.IsBuiltin {
		existing.Enabled = update.Enabled
	} else {
		existing.Name = update.Name
		existing.Category = update.Category
		existing.Protocol = update.Protocol
		existing.SrcPort = update.SrcPort
		existing.DstPort = update.DstPort
		existing.Payload = update.Payload
		existing.Action = update.Action
		existing.PPSLimit = update.PPSLimit
		existing.Enabled = update.Enabled
	}

	if err := h.DB.Save(&existing).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "시그니처 업데이트 실패"})
	}

	return c.JSON(existing)
}

// DeleteSignature - Delete an attack signature
func (h *Handler) DeleteSignature(c *fiber.Ctx) error {
	id := c.Params("id")

	var sig models.AttackSignature
	if err := h.DB.First(&sig, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "시그니처를 찾을 수 없습니다"})
	}

	// Cannot delete builtin signatures
	if sig.IsBuiltin {
		return c.Status(403).JSON(fiber.Map{"error": "기본 시그니처는 삭제할 수 없습니다"})
	}

	if err := h.DB.Delete(&sig).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "시그니처 삭제 실패"})
	}

	return c.JSON(fiber.Map{"message": "시그니처가 삭제되었습니다"})
}

// ResetSignatureStats - Reset hit count for all signatures
func (h *Handler) ResetSignatureStats(c *fiber.Ctx) error {
	if err := h.DB.Model(&models.AttackSignature{}).Updates(map[string]interface{}{
		"hit_count": 0,
		"last_hit":  nil,
	}).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "통계 초기화 실패"})
	}
	return c.JSON(fiber.Map{"message": "시그니처 통계가 초기화되었습니다"})
}
