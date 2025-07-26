document.addEventListener('DOMContentLoaded', function () {
    // Lấy danh sách các thông báo
    const flashes = document.querySelector('.flashes');
    
    if (flashes) {
        // Tự động ẩn thông báo sau 5 giây
        setTimeout(() => {
            flashes.style.transition = "opacity 0.5s ease";
            flashes.style.opacity = "0"; // Làm mờ
            setTimeout(() => flashes.remove(), 500); // Xóa khỏi DOM sau hiệu ứng
        }, 5000);

        // Gắn sự kiện click để xóa thông báo ngay lập tức khi nhấn
        flashes.addEventListener('click', function () {
            flashes.style.transition = "opacity 0.3s ease";
            flashes.style.opacity = "0";
            setTimeout(() => flashes.remove(), 300);
        });
    }
});
