package webhook

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	core "github.com/sns45/assayward/pkg/core"
)

// podImages extracts image references from all container types in a Pod spec.
// It covers spec.containers, spec.initContainers, and spec.ephemeralContainers.
// Each image string is parsed into a core.ImageRef by splitting on the last "@":
//   - "registry/repo@sha256:abc" -> ImageRef{Name: "registry/repo", Digest: "sha256:abc"}
//   - "registry/repo:tag"        -> ImageRef{Name: "registry/repo:tag", Digest: ""}
func podImages(pod *corev1.Pod) []core.ImageRef {
	var refs []core.ImageRef

	for _, c := range pod.Spec.Containers {
		refs = append(refs, parseImageRef(c.Image))
	}
	for _, c := range pod.Spec.InitContainers {
		refs = append(refs, parseImageRef(c.Image))
	}
	for _, c := range pod.Spec.EphemeralContainers {
		refs = append(refs, parseImageRef(c.Image))
	}

	return refs
}

// parseImageRef splits an image string on the last "@" to extract name and digest.
// If there is no "@", Digest is empty and Name is the full image string (may include tag).
func parseImageRef(image string) core.ImageRef {
	if idx := strings.LastIndex(image, "@"); idx >= 0 {
		return core.ImageRef{
			Name:   image[:idx],
			Digest: image[idx+1:],
		}
	}
	return core.ImageRef{
		Name:   image,
		Digest: "",
	}
}
