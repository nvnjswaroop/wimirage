document.addEventListener("DOMContentLoaded", function () {
    const otpBoxes = document.querySelectorAll(".otp-box");
    const otpHidden = document.getElementById("otpHidden");
    const otpForm = document.getElementById("otpForm");

    if (otpBoxes.length && otpHidden) {
        otpBoxes[0].focus();

        otpBoxes.forEach(function (box, index) {
            box.addEventListener("input", function (e) {
                var value = e.target.value.replace(/[^0-9]/g, "");
                e.target.value = value;

                if (value && index < otpBoxes.length - 1) {
                    otpBoxes[index + 1].focus();
                }

                var fullOtp = "";
                otpBoxes.forEach(function (b) {
                    fullOtp += b.value;
                });
                otpHidden.value = fullOtp;

                if (fullOtp.length === otpBoxes.length) {
                    otpForm.submit();
                }
            });

            box.addEventListener("keydown", function (e) {
                if (e.key === "Backspace" && !e.target.value && index > 0) {
                    otpBoxes[index - 1].focus();
                }
            });

            box.addEventListener("paste", function (e) {
                e.preventDefault();
                var paste = (e.clipboardData || window.clipboardData).getData("text").replace(/[^0-9]/g, "");
                if (paste.length >= otpBoxes.length) {
                    for (var i = 0; i < otpBoxes.length; i++) {
                        otpBoxes[i].value = paste[i] || "";
                    }
                    var fullOtp = "";
                    otpBoxes.forEach(function (b) {
                        fullOtp += b.value;
                    });
                    otpHidden.value = fullOtp;
                    otpBoxes[otpBoxes.length - 1].focus();
                    otpForm.submit();
                }
            });
        });
    }

    var countdownEl = document.getElementById("countdown");
    if (countdownEl) {
        var totalSeconds = 300;
        var timerInterval = setInterval(function () {
            totalSeconds--;
            if (totalSeconds <= 0) {
                clearInterval(timerInterval);
                countdownEl.textContent = "Expired";
                return;
            }
            var minutes = Math.floor(totalSeconds / 60);
            var seconds = totalSeconds % 60;
            countdownEl.textContent = minutes + ":" + (seconds < 10 ? "0" : "") + seconds;
        }, 1000);
    }

    var resendBtn = document.getElementById("resendBtn");
    if (resendBtn) {
        resendBtn.addEventListener("click", function () {
            this.disabled = true;
            this.textContent = "Sending...";
            var self = this;
            setTimeout(function () {
                self.disabled = false;
                self.textContent = "Resend OTP";
            }, 30000);
        });
    }

    var loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", function (e) {
            var phone = document.getElementById("phone");
            var email = document.getElementById("email");
            if (phone && !phone.value.match(/^[0-9]{7,15}$/)) {
                e.preventDefault();
                alert("Please enter a valid phone number.");
                return;
            }
            if (email && !email.value.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
                e.preventDefault();
                alert("Please enter a valid email address.");
                return;
            }
        });
    }
});
