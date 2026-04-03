# QUẢN LÝ MẬT KHẨU CÁ NHÂN
## Mô tả chi tiết
 Phát triển hệ thống quản lý mật khẩu cá nhân bằng Python, tập trung vào bảo mật dữ liệu. Ứng dụng cho phép người dùng lưu trữ và quản lý thông tin tài khoản (thêm, sửa, xóa) một cách an toàn thông qua các cơ chế bảo mật hiện đại.
 - Hệ thống triển khai xác thực hai yếu tố (2FA) sử dụng Google Authenticator dựa trên chuẩn TOTP (Time-based One-Time Password). Sử dụng thư viện PyOTP để tạo và xác thực mã OTP theo thời gian thực, giúp tăng cường bảo mật trong quá trình đăng nhập và hạn chế truy cập trái phép.
 - Dữ liệu nhạy cảm như mật khẩu được bảo vệ bằng kỹ thuật hashing (bcrypt/sha256), đảm bảo không lưu trữ dưới dạng plain text. Đồng thời, hệ thống thiết kế cơ chế xác thực và quản lý session để duy trì trạng thái đăng nhập an toàn.
 - Cơ sở dữ liệu (SQLite) được thiết kế có cấu trúc rõ ràng, tối ưu cho việc lưu trữ thông tin người dùng và các bản ghi mật khẩu. Các thao tác CRUD được xây dựng đầy đủ, đảm bảo khả năng truy xuất nhanh và chính xác.
 - Ngoài ra có có các tính năng nâng cao như: Sao lưu dữ liệu vào khóa, Nhập khóa để khôi phục dữ liệu, Thay đổi thiết bị lấy mã OTP (One-Time Password), Lấy lại tài khoản khi đã mất thiết bị nhận mã OTP.
## Tech Stack
 - Ngôn ngữ: Python
 - Framework: Flask
 - Bảo mật: PyOTP (TOTP), Hashing (bcrypt/sha256/AES)
 - Cơ sở dữ liệu: SQLite
 - Frontend: HTML, CSS, JavaScript
