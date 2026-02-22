package cloud

import (
	"context"
	"mime/multipart"

	"ampli/api/internal/config"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
)

// Client wraps the Cloudinary SDK.
type Client struct {
	cld *cloudinary.Cloudinary
}

func New(cfg *config.Config) *Client {
	cld, err := cloudinary.NewFromParams(cfg.CloudName, cfg.CloudKey, cfg.CloudSecret)
	if err != nil {
		panic("failed to initialize cloudinary: " + err.Error())
	}
	return &Client{cld: cld}
}

type UploadResult struct {
	URL      string
	PublicID string
}

// UploadAvatar uploads a 300x300 face-cropped image (for user avatars).
func (c *Client) UploadAvatar(ctx context.Context, file multipart.File) (*UploadResult, error) {
	resp, err := c.cld.Upload.Upload(ctx, file, uploader.UploadParams{
		ResourceType:   "image",
		Transformation: "c_thumb,w_300,h_300,g_face",
	})
	if err != nil {
		return nil, err
	}
	return &UploadResult{URL: resp.SecureURL, PublicID: resp.PublicID}, nil
}

// UploadPoster uploads a 300x300 face-cropped image (for audio posters).
func (c *Client) UploadPoster(ctx context.Context, file multipart.File) (*UploadResult, error) {
	resp, err := c.cld.Upload.Upload(ctx, file, uploader.UploadParams{
		ResourceType:   "image",
		Transformation: "c_thumb,w_300,h_300,g_face",
	})
	if err != nil {
		return nil, err
	}
	return &UploadResult{URL: resp.SecureURL, PublicID: resp.PublicID}, nil
}

// UploadAudio uploads an audio/video file.
func (c *Client) UploadAudio(ctx context.Context, file multipart.File) (*UploadResult, error) {
	resp, err := c.cld.Upload.Upload(ctx, file, uploader.UploadParams{
		ResourceType: "video",
	})
	if err != nil {
		return nil, err
	}
	return &UploadResult{URL: resp.SecureURL, PublicID: resp.PublicID}, nil
}

// DestroyImage removes an image asset from Cloudinary.
func (c *Client) DestroyImage(ctx context.Context, publicID string) error {
	_, err := c.cld.Upload.Destroy(ctx, uploader.DestroyParams{
		PublicID:     publicID,
		ResourceType: "image",
	})
	return err
}

// DestroyAudio removes an audio/video asset from Cloudinary.
func (c *Client) DestroyAudio(ctx context.Context, publicID string) error {
	_, err := c.cld.Upload.Destroy(ctx, uploader.DestroyParams{
		PublicID:     publicID,
		ResourceType: "video",
	})
	return err
}
