package webhook

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	core "github.com/sns45/assayward/pkg/core"
)

func TestPodImages_AllContainerTypes(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "registry.example.com/app:v1.0"},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Image: "registry.example.com/init:v1.0"},
			},
			EphemeralContainers: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  "debug",
					Image: "registry.example.com/debug:latest",
				}},
			},
		},
	}

	imgs := podImages(pod)

	if len(imgs) != 3 {
		t.Fatalf("expected 3 images, got %d: %v", len(imgs), imgs)
	}

	// All should be tag-only, so Digest should be empty
	for _, img := range imgs {
		if img.Digest != "" {
			t.Errorf("expected empty digest for tag-only image %q, got %q", img.Name, img.Digest)
		}
	}
}

func TestPodImages_DigestParsing(t *testing.T) {
	cases := []struct {
		imageStr       string
		expectedName   string
		expectedDigest string
	}{
		{
			imageStr:       "registry.example.com/app@sha256:abc123def456",
			expectedName:   "registry.example.com/app",
			expectedDigest: "sha256:abc123def456",
		},
		{
			imageStr:       "registry.example.com/app:v1.2@sha256:deadbeef",
			expectedName:   "registry.example.com/app:v1.2",
			expectedDigest: "sha256:deadbeef",
		},
		{
			imageStr:       "registry.example.com/app:latest",
			expectedName:   "registry.example.com/app:latest",
			expectedDigest: "",
		},
		{
			imageStr:       "ubuntu",
			expectedName:   "ubuntu",
			expectedDigest: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.imageStr, func(t *testing.T) {
			pod := &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c", Image: tc.imageStr},
					},
				},
			}
			imgs := podImages(pod)
			if len(imgs) != 1 {
				t.Fatalf("expected 1 image, got %d", len(imgs))
			}
			got := imgs[0]
			if got.Name != tc.expectedName {
				t.Errorf("Name: got %q want %q", got.Name, tc.expectedName)
			}
			if got.Digest != tc.expectedDigest {
				t.Errorf("Digest: got %q want %q", got.Digest, tc.expectedDigest)
			}
		})
	}
}

func TestPodImages_MultiContainer(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "a", Image: "img-a:1"},
				{Name: "b", Image: "img-b@sha256:cafebabe"},
			},
			InitContainers: []corev1.Container{
				{Name: "init1", Image: "img-init:1"},
				{Name: "init2", Image: "img-init2@sha256:deadbeef"},
			},
		},
	}

	imgs := podImages(pod)
	if len(imgs) != 4 {
		t.Fatalf("expected 4 images, got %d", len(imgs))
	}

	// Build a map for easy lookup
	byName := make(map[string]core.ImageRef)
	for _, img := range imgs {
		byName[img.Name] = img
	}

	if _, ok := byName["img-a:1"]; !ok {
		t.Error("missing img-a:1")
	}
	if ref, ok := byName["img-b"]; !ok {
		t.Error("missing img-b")
	} else if ref.Digest != "sha256:cafebabe" {
		t.Errorf("img-b wrong digest: %q", ref.Digest)
	}
	if _, ok := byName["img-init:1"]; !ok {
		t.Error("missing img-init:1")
	}
	if ref, ok := byName["img-init2"]; !ok {
		t.Error("missing img-init2")
	} else if ref.Digest != "sha256:deadbeef" {
		t.Errorf("img-init2 wrong digest: %q", ref.Digest)
	}
}

func TestPodImages_EmptyPod(t *testing.T) {
	pod := &corev1.Pod{}
	imgs := podImages(pod)
	if len(imgs) != 0 {
		t.Errorf("expected 0 images for empty pod, got %d", len(imgs))
	}
}
