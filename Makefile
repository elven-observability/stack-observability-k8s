PYTHON ?= python3

.PHONY: validate runtime integration images-check
validate:
	$(PYTHON) scripts/validate.py

runtime:
	@test -n "$(ELVEN_COLLECTOR_IMAGE)" || (echo 'Set ELVEN_COLLECTOR_IMAGE to the exact corrected Elven digest; do not substitute the vulnerable full upstream.' >&2; exit 1)
	$(PYTHON) scripts/validate.py --runtime

# Disposable Kind only; never uses the caller's active Kubernetes context.
integration:
	@test -n "$(ELVEN_COLLECTOR_IMAGE)" || (echo 'Set ELVEN_COLLECTOR_IMAGE to the exact Elven digest.' >&2; exit 1)
	$(PYTHON) scripts/test-kind.py --development-images

images-check:
	$(PYTHON) scripts/images-release.py check
