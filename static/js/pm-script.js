///__________Ẩn hiện các form__________///
// ---- Ẩn hiện sidebar ---- //
let sidebar = document.querySelector(".sidebar");
let closeBtn = document.querySelector("#btn");

closeBtn.addEventListener("click", () => {
    sidebar.classList.toggle("open");
    menuBtnChange();
});

function menuBtnChange() {
    if (sidebar.classList.contains("open")) {
        closeBtn.classList.replace("bx-menu", "bx-menu-alt-right");
    } else {
        closeBtn.classList.replace("bx-menu-alt-right", "bx-menu");
    }
}

// ---- Ẩn hiện các form ---- //
document.addEventListener("DOMContentLoaded", function() {
    // ---- Const các nút bấm ---- //
    // Nút sidebar
    const mailReceivedBtn = document.querySelector('.mail-received');
    const mailSendBtn = document.querySelector('.mail-send');

    // ---- Const các form ---- //
    // Form sidebar
    const formMailReceived = document.querySelector('.form-mail-received');
    const formMailSend = document.querySelector('.form-mail-send');

    // Mặc định hiển thị form thư đến
    formMailReceived.classList.add('active');

    // Reset form trước khi chuyển đổi form khác
    function resetForms() {
        formMailReceived.classList.remove('active');
        formMailSend.classList.remove('active');
    }

    // ----- Mở form liên kết với nút bên sidebar ----- //
    // Mở form thư đến
    mailReceivedBtn.addEventListener('click', function() {
        resetForms();
        formMailReceived.classList.add('active');
    });

    // Mở form thư đã gửi
    mailSendBtn.addEventListener('click', function() {
        resetForms();
        formMailSend.classList.add('active');
    });
});
///__________Phân trang danh sách thư của các form__________///
document.addEventListener('DOMContentLoaded', function() {
    const rowsPerPage = 8;

    function paginateTable(table) {
        const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
        const paginationControls = table.nextElementSibling;
        let currentPage = 1;    

        function displayRows() {
            const startRow = (currentPage - 1) * rowsPerPage;
            const endRow = startRow + rowsPerPage;
            for (let i = 0; i < rows.length; i++) {
                rows[i].style.display = i >= startRow && i < endRow ? '' : 'none';
            }
        }

        function setupPagination() {
            const pageCount = Math.ceil(rows.length / rowsPerPage);
            paginationControls.innerHTML = '';

            for (let i = 1; i <= pageCount; i++) {
                const pageButton = document.createElement('button');
                pageButton.textContent = i;
                pageButton.classList.add('page-button');
                pageButton.addEventListener('click', function() {
                    currentPage = i;
                    displayRows();
                    highlightCurrentPage();
                });
                paginationControls.appendChild(pageButton);
            }
        }

        function highlightCurrentPage() {
            const buttons = paginationControls.getElementsByClassName('page-button');
            for (let button of buttons) {
                button.style.backgroundColor = button.textContent == currentPage ? '#007BFF' : '#f5f5f5';
                button.style.color = button.textContent == currentPage ? '#FFF' : '#000';
            }
        }

        displayRows();
        setupPagination();
        highlightCurrentPage();
    }

    // Lặp qua tất cả các bảng email-table để phân trang
    document.querySelectorAll('.email-table').forEach(table => {
        paginateTable(table);
    });
});

// Ẩn hiện mk
function togglePassword(button) {
    const passwordField = button.parentElement.previousElementSibling.firstElementChild;
    if (passwordField.type === "password") {
        passwordField.type = "text";
        button.textContent = "Ẩn";
    } else {
        passwordField.type = "password";
        button.textContent = "Hiện";
    }
}

document.querySelector('.show-face-id').addEventListener('click', function() {
    const faceIdForm = document.querySelector('.form-face-id');
    faceIdForm.classList.toggle('active');
});





