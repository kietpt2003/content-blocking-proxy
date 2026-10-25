# Content Blocking Proxy

Proxy HTTP/HTTPS chạy tập trung trên home server, cấu hình bằng YAML và tự nạp lại
khi file thay đổi. Đây là project Python độc lập, không chạy trên ESP32 và không
thay đổi firmware hay cấu hình DNS/router hiện có.

## Phạm vi

- Chặn request theo domain, subdomain và regex đường dẫn/query.
- Allow rule ưu tiên hơn block và bộ lọc nội dung.
- Xóa trường JSON và phần tử danh sách khớp điều kiện rõ ràng, giữ nguyên dữ liệu khác.
- Chèn CSS ẩn thành phần quảng cáo trong HTML UTF-8 nếu trang không có CSP ngăn inline style.
- Cấu hình lỗi khi reload: tiếp tục dùng bản hợp lệ trước đó, ghi nhận trong status.
- Stream video, tải xuống và response lớn; chỉ đệm nội dung ứng viên tối đa 2 MiB.
- Thống kê cục bộ dạng JSON; mặc định không ghi flow, cookie hoặc body request/response.
  Log vận hành của mitmproxy có thể chứa IP/hostname và lỗi kết nối.

**Không cam kết YouTube/Facebook hết quảng cáo.** Quy tắc YouTube đi kèm chỉ xử lý
các trường/renderer nhận diện được trong JSON thuần. HTML có JSON nhúng trong script,
GraphQL dạng batch/anti-XSSI, protobuf, WebSocket và định dạng khác được giữ nguyên.
Quy tắc Facebook là ví dụ opt-in, không bật mặc định và chưa kiểm chứng trên dịch vụ thật.
Không sửa subscription, xác thực, DRM hay URL luồng video.

## Chạy bằng Docker Compose trên home server

Yêu cầu Docker Engine và Docker Compose v2, Linux/macOS, kiến trúc mà dependency hỗ trợ.

```bash
cp .env.example .env
docker compose build
docker compose run --rm proxy check --config /app/config/proxy.yaml
docker compose up -d
docker compose ps
docker compose logs --tail=50 proxy
```

Mặc định chỉ mở `127.0.0.1:8080` của home server. Để thiết bị khác truy cập:

1. Gán IP cố định cho home server trên router.
2. Sửa `.env`, ví dụ `PROXY_BIND=192.168.1.20` (thay bằng IP thật của server).
3. `docker compose up -d` để áp dụng thay đổi cổng bind.
4. Cho phép TCP/8080 từ các subnet LAN cần dùng trong firewall của server.

Không mở port proxy ra Internet. Proxy không có đăng nhập người dùng; giới hạn truy cập
bằng LAN bind/firewall. Docker có quy tắc firewall riêng, cần kiểm tra cổng publish
thực tế thay vì chỉ dựa vào cấu hình UFW. Không tắt xác minh TLS upstream.

## Chạy trực tiếp bằng Python

Yêu cầu Python 3.12 trở lên; đã kiểm thử cục bộ với Python 3.13.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
content-proxy check --config config/proxy.yaml
content-proxy run --config config/proxy.yaml --state-dir state
```

Mặc định lắng nghe `127.0.0.1:8080`. Chạy LAN bằng
`--listen-host <IP-LAN-HOME-SERVER>`. Dừng bằng Ctrl+C.
CA và thống kê nằm trong `state/`, đã được gitignore.
Nếu upstream riêng dùng CA nội bộ, truyền `--upstream-ca /path/to/ca.pem`.

## Dùng trên thiết bị thử nghiệm

1. Đặt HTTP/HTTPS proxy của thiết bị hoặc trình duyệt thành IP home server, cổng 8080.
2. Khi đã bật proxy, mở **http://mitm.it** trên thiết bị để lấy chứng chỉ CA.
3. Cài và bật tin cậy CA theo hệ điều hành/trình duyệt. Nếu chưa tin CA, HTTPS sẽ lỗi.
4. Thử website HTTP/HTTPS trước, rồi xem các bộ đếm tại server.
5. Khi ngừng dùng, gỡ cấu hình proxy và CA khỏi thiết bị thử nghiệm.

Đây là chứng chỉ để proxy giải mã HTTPS. Khóa riêng CA phải nằm trên server;
chỉ phân phối file chứng chỉ công khai, tuyệt đối không phân phối `mitmproxy-ca.pem`.
Với Docker, CA được giữ trong named volume `proxy-state`, qua các lần restart/rebuild.
`docker compose down` giữ volume; **`docker compose down -v` xóa CA**, khi đó các
thiết bị phải cài lại chứng chỉ do server mới tạo.

Xuất chứng chỉ công khai ra máy chạy Docker:

```bash
mkdir -p state
docker compose cp proxy:/state/mitmproxy/mitmproxy-ca-cert.pem state/proxy-ca-cert.pem
```

Một số ứng dụng không dùng proxy hệ thống, không tin CA do người dùng cài hoặc có
certificate pinning. Với các ứng dụng này không thể hứa lọc nội dung HTTPS. Project
không bao gồm cách vượt pinning, sửa APK hoặc cài chứng chỉ bí mật vào thiết bị.

## Cấu hình tập trung

Chỉnh `config/proxy.yaml`; proxy kiểm tra thay đổi mỗi 2 giây. Mount cả thư mục `config/`
để thao tác lưu file bằng đổi tên của editor cũng được nhận diện trong Docker.

```bash
docker compose exec proxy content-proxy check --config /app/config/proxy.yaml
docker compose exec proxy content-proxy status --state-dir /state
```

Hoặc khi chạy Python trực tiếp:

```bash
content-proxy check
content-proxy status
```

`check` kiểm tra file trên đĩa; `status.policy_reload_error` cho biết proxy hiện có đang
giữ cấu hình cũ vì file mới bị lỗi không. Counter reset khi tiến trình restart; CA không reset.
Đặt `enabled: false` để tạm dừng mọi bộ lọc, vẫn giữ proxy chuyển tiếp.

Ví dụ quy tắc URL (domain `example.com` và mọi subdomain):

```yaml
block_rules:
  - id: example-ad-path
    domains: [example.com]
    path_regex: '^/advertising/'
```

`path_regex` là regex Python trên path + query, phân biệt hoa thường; không khớp
scheme hoặc hostname. Không dùng regex tốn thời gian/không tin cậy. Domain dùng ASCII
hoặc punycode, không có `https://`, wildcard hay path; `*` khớp mọi host.
Đây không phải parser EasyList/ABP: không dán trực tiếp filter list của extension vào YAML.
Mỗi id là duy nhất trên toàn bộ policy. Allow rules có cùng cấu trúc với block rules.

Ví dụ nội dung JSON:

```yaml
json_rules:
  - id: example-sponsored
    domains: [example.com]
    path_regex: '^/api/feed'
    remove_keys: [adPlacements]
    remove_items_with_keys: [adSlotRenderer]
    remove_items_where:
      - path: [node, is_sponsored]
        equals: true
```

`remove_keys` xóa key ở mọi độ sâu trong response khớp rule.
`remove_items_with_keys` bỏ phần tử object trong array nếu nó có key chỉ định ngay
trên object đó. `remove_items_where` bỏ phần tử array nếu đường dẫn trường khớp đúng
giá trị và kiểu; boolean `true` không khớp số `1`. Chỉ dùng các key đã xác nhận là quảng cáo
trong response thực tế để tránh xóa nhầm nội dung. Không tự suy luận từ chữ "Sponsored".

Khi body thay đổi, proxy cập nhật Content-Length, bỏ encoding cũ và các digest/ETag,
đặt Cache-Control no-store. Body giữ nguyên nếu không có phần tử khớp.
Response không phải status 200, JSON sai định dạng, body quá lớn, encoding không hỗ trợ
hoặc độ sâu JSON quá 128 sẽ không bị sửa. Với response cần lọc, proxy yêu cầu upstream
gửi `identity`; vẫn hỗ trợ gzip với giới hạn giải nén. Brotli/zstd giữ nguyên nếu upstream
vẫn gửi chúng. CSS không được chèn vào HTML có CSP; proxy không gỡ CSP của website.

## Tích hợp router/DNS sau này

**Đổi DNS không tự đưa HTTP/HTTPS qua proxy.** ESP32 vẫn có thể lọc DNS ở cổng 53;
project này nhận lưu lượng proxy ở cổng 8080. Không trỏ bản ghi DNS của YouTube/Facebook
về IP proxy: cách đó làm sai TLS/SNI và không tạo ra kết nối proxy hợp lệ.

Hai hướng triển khai:

- **Explicit proxy (mặc định):** thiết bị/trình duyệt dùng proxy qua thiết lập thủ công
  hoặc PAC/MDM. Cấu hình bộ lọc quản lý tại server; thiết bị vẫn cần đường đi tới proxy
  và tin cậy CA. PAC chỉ hướng lưu lượng, không tự cấp quyền tin cậy chứng chỉ.
- **Transparent proxy (Linux, triển khai sau):** server/gateway phải nằm trên đường
  đi của lưu lượng, router/firewall chuyển hướng TCP HTTP/HTTPS tới proxy. CLI hỗ trợ
  `--mode transparent`, nhưng project không tự thay NAT, routing, firewall hay gateway.
  Phải thiết kế tuyến đi/về, loại trừ lưu lượng của chính proxy và của server khỏi redirect.

Với mạng ZTE `192.168.1.1` → Deco `192.168.68.1`, ESP32 `192.168.1.9`, home server
cần IP riêng và route từ các thiết bị sau Deco. Không dùng IP ESP32 cho server.
Một rule redirect trên ZTE không đảm bảo bắt được lưu lượng nội bộ cùng subnet hoặc
thiết bị có tuyến khác. QUIC/HTTP3 qua UDP/443 có thể đi ngoài tuyến redirect TCP;
DoH, VPN, ứng dụng bỏ qua proxy và pinning cũng cần xét theo thiết bị/topology.
Không tự động bật redirect toàn mạng trước khi kiểm thử một thiết bị.

## Kiểm thử

```bash
python -m pip install -e '.[dev]'
ruff check src tests scripts
pytest -q
python scripts/smoke_test.py
```

Smoke test tạo HTTP và HTTPS upstream cục bộ, tạo CA dùng thử, cấu hình proxy tin CA
upstream đó và cấu hình curl tin CA proxy. Không dùng `-k`/`ssl_insecure`, không gọi
YouTube/Facebook thật, không thay proxy hệ thống của máy. Kiểm tra chặn URL, allow,
JSON/gzip, HTML/CSP, media giữ nguyên, response lớn và live reload lỗi/hợp lệ.
Tất cả tiến trình/port thử nghiệm được đóng khi kết thúc.

Docker build và tích hợp router/thiết bị thật cần kiểm tra trên home server đích.
Kết quả fixture không chứng minh loại được quảng cáo trên YouTube/Facebook thực tế.

## Tài liệu nền

- [mitmproxy — proxy modes](https://docs.mitmproxy.org/stable/concepts/modes/)
- [mitmproxy — certificates](https://docs.mitmproxy.org/stable/concepts/certificates/)
- [mitmproxy — transparent routing](https://docs.mitmproxy.org/stable/howto-transparent/)
- [mitmproxy — application compatibility / ignored hosts](https://docs.mitmproxy.org/stable/howto-ignoredomains/)

