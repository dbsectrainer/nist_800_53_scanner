document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("login-form");
  const errorMessage = document.getElementById("error-message");

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    try {
      const response = await fetch("/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok) {
        // Store authentication token
        localStorage.setItem("authToken", data.token);
        localStorage.setItem("username", data.user.username);

        // Redirect to dashboard
        window.location.href = "/dashboard";
      } else {
        // Display error message
        errorMessage.textContent = data.message || "Login failed";
      }
    } catch (error) {
      console.error("Login error:", error);
      errorMessage.textContent = "Network error. Please try again.";
    }
  });
});
