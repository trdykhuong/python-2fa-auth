document.getElementById('new_password').addEventListener('input', function () {
    const password = this.value;
    const strengthIndicator = document.getElementById('password-strength');
    let strength = 0;

    // Kiểm tra độ dài
    if (password.length >= 8) strength++;

    // Kiểm tra ký tự đặc biệt
    if (/[!@#$%^&*(),.?":{}|<>]/g.test(password)) strength++;

    // Kiểm tra chữ hoa và chữ thường
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;

    // Kiểm tra chữ số
    if (/\d/.test(password)) strength++;

    // Gợi ý độ mạnh của mật khẩu
    switch (strength) {
        case 0:
            strengthIndicator.textContent = '';
            break;
        case 1:
            strengthIndicator.textContent = 'Yếu: Nên thêm ký tự đặc biệt và chữ số.';
            strengthIndicator.style.color = 'red';
            break;
        case 2:
            strengthIndicator.textContent = 'Trung bình: Tăng độ dài hoặc thêm ký tự đặc biệt.';
            strengthIndicator.style.color = 'orange';
            break;
        case 3:
            strengthIndicator.textContent = 'Khá mạnh: Có thể sử dụng được.';
            strengthIndicator.style.color = 'blue';
            break;
        case 4:
            strengthIndicator.textContent = 'Mạnh: Mật khẩu an toàn.';
            strengthIndicator.style.color = 'green';
            break;
    }
});

