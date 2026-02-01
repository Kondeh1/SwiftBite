const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const tick = document.getElementById("tick");
const continueBtn = document.getElementById("continueBtn");
const nameInput = document.getElementById("name");
const roleSelect = document.getElementById("role");
const track = document.getElementById("carouselTrack");
const dots = document.querySelectorAll(".dot");
const alreadyExist = document.querySelector(".userExist");


let index = 0;

function updateCarousel() {
  index++;
  if (index >= dots.length) index = 0;

  track.style.transform = `translateX(-${index * 50}%)`;

  dots.forEach((dot, i) => {
    dot.classList.toggle("active", i === index);
  });
}

// continueBtn.addEventListener("click", () => {
//   alert("I got clicked");
// });

setInterval(updateCarousel, 3000);

togglePassword.addEventListener("click", () => {
  const type =
    passwordInput.getAttribute("type") === "password" ? "text" : "password";
  passwordInput.setAttribute("type", type);
  const icon = togglePassword.querySelector("i");
  icon.className =
    type === "password" ? "fa-solid fa-eye-slash" : "fa-solid fa-eye";
});

const validateEmail = (email) => {
  return String(email)
    .toLowerCase()
    .match(
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
    );
};

const updateUI = () => {
  const isEmailValid = validateEmail(emailInput.value);
  const hasPassword = passwordInput.value.length >= 1;
  const isNameValid = !nameInput || nameInput.value.trim().length > 0;
  const isRoleValid = !roleSelect || roleSelect.value !== "";

  tick.style.display = isEmailValid ? "block" : "none";

  if (isEmailValid && hasPassword && isNameValid && isRoleValid) {
    continueBtn.disabled = false;
    continueBtn.classList.add("active");
  } else {
    continueBtn.disabled = true;
    continueBtn.classList.remove("active");
  }
};

emailInput.addEventListener("input", updateUI);
passwordInput.addEventListener("input", updateUI);
if (nameInput) nameInput.addEventListener("input", updateUI);
if (roleSelect) roleSelect.addEventListener("change", updateUI);

// setTimeout(alreadyExist, 1000);

if (alreadyExist) {
  setTimeout(() => {
    alreadyExist.classList.add("hidden");
  }, 3000);
}
