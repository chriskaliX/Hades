INFO_COLOR = \033[34m[*]\033[0m

hboat_cmd: \
	pre_show
	go build -o hboat cmd/main.go

.PHONY: pre_show
pre_show:
	@echo "┌──────────────────────────────┐"
	@printf "│   \033[35mHboat\033[0m (Hades Server Side)  │\n"
	@echo "│         @chriskaliX          │"
	@echo "└──────────────────────────────┘"
	@printf "$(INFO_COLOR) Clean for the old hboat...\n"
	$(MAKE) clean -s --no-print-directory
	@printf "$(INFO_COLOR) Start to build Cmd tool\n"

.PHONY: clean
clean:
	rm -f hboat

.PHONY: build
build:
	cd frontend && npm run build && cd ..

.PHONY: build_frontend
build_frontend:
	rm -f api/static/frontend/*
	cd frontend && npm run build && cd ..
	cp frontend/dist/* api/static/frontend/