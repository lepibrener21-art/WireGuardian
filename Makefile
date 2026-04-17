.PHONY: setup setup-server setup-client clean

setup: setup-server setup-client

setup-server:
	python3 -m venv .venv-server
	.venv-server/bin/pip install --quiet --upgrade pip
	.venv-server/bin/pip install --quiet -e ".[server]"
	@echo "Server venv ready. Use ./wg-server or .venv-server/bin/wg-server"

setup-client:
	python3 -m venv .venv-client
	.venv-client/bin/pip install --quiet --upgrade pip
	.venv-client/bin/pip install --quiet -e ".[client]"
	@echo "Client venv ready. Use ./wg-client or .venv-client/bin/wg-client"

clean:
	rm -rf .venv-server .venv-client wireguardian.egg-info
