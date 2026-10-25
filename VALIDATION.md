# Kết quả kiểm tra — 25/10/2026

Môi trường: macOS arm64, Python 3.13, mitmproxy 12.3.0.

- Ruff lint và format: PASS.
- Pytest: 16 bài PASS.
- Cấu hình mặc định: PASS (4 request block rules, 1 JSON rule, 1 HTML rule).
- Smoke test thực tế trên HTTP và HTTPS localhost: PASS.
- HTTPS upstream được xác minh bằng CA thử nghiệm; curl xác minh CA proxy.
  Không dùng tùy chọn bỏ xác minh TLS ở cả hai chặng.
- Chặn URL trả 204, không gửi HTTP request đến upstream; allowlist có ưu tiên.
- JSON/gzip được lọc, giữ nội dung thường và media metadata.
- CSS chỉ chèn vào HTML phù hợp; HTML có CSP và media giữ nguyên.
- JSON lớn hơn 2 MiB được stream và giữ nguyên.
- Reload YAML lỗi giữ policy hợp lệ trước đó; enabled=false được áp dụng.
- Entry point từ project riêng và build wheel Python: PASS.
- Cấu trúc YAML Compose: PASS, chưa thay thế được docker compose config/build.
- Proxy và các upstream thử nghiệm được dừng trong teardown của smoke test.

Chưa kiểm chứng:

- Docker build/runtime: máy hiện tại không có Docker CLI/daemon.
- Linux home server, router/NAT/transparent mode, thiết bị qua Deco.
- Quảng cáo YouTube/Facebook thật, ứng dụng có pinning, HTTP/3.
- Tải đồng thời nhiều thiết bị hoặc chạy liên tục dài ngày.

Project có workflow CI kiểm tra Python và Docker khi đưa lên GitHub.
