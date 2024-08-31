import { useState, useContext, useEffect } from "react";
import { UserContext } from "../context/UserContext";
import { Link, useNavigate } from "react-router-dom";

export default function Login() {
  const [userCreds, setUserCreds] = useState({ email: "", password: "" });
  const [message, setMessage] = useState({ type: "invisible-msg", text: "Dummy Msg" });
  const navigate = useNavigate();
  const loggedData = useContext(UserContext);

  useEffect(() => {
    fetchCsrfToken();
  }, []);

  async function fetchCsrfToken() {
    try {
      const response = await fetch("http://localhost:8000/csrf-token", { credentials: 'include' });
      const { csrfToken } = await response.json();
      if (csrfToken) {
        document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; SameSite=Strict; path=/`;
      }
    } catch (error) {
      console.error('Error fetching CSRF token:', error);
    }
  }

  function handleInput(event) {
    setUserCreds((prevState) => ({
      ...prevState,
      [event.target.name]: event.target.value
    }));
  }

  async function handleSubmit(event) {
    event.preventDefault();

    try {
      const csrfCookie = document.cookie.replace(/(?:(?:^|.*;\s*)XSRF-TOKEN\s*=\s*([^;]*).*$)|^.*$/, "$1");

      const response = await fetch("http://localhost:8000/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CSRF-Token": csrfCookie
        },
        body: JSON.stringify(userCreds),
        credentials: 'include'
      });

      if (response.status === 404) {
        console.log('404 error handling'); 
        setMessage({ type: "error", text: "Email Bulunamadı!" });
        throw new Error("Email not found.");
      } else if (response.status === 403) {
        setMessage({ type: "error", text: "Hatalı Şifre!" });
        throw new Error("Hatalı Şifre!");
      } else if (!response.ok) {
        setMessage({ type: "error", text: "Bir hata oluştu. Lütfen daha sonra tekrar deneyiniz." }); // Generic error
        throw new Error("An error occurred.");
    }

      const data = await response.json();

      if (data.token && data.isVerified) {
        const userData = { ...data }; // Store entire user data including token
        localStorage.setItem("app-user", JSON.stringify(userData));
        loggedData.setLoggedUser(userData); // Update context
        navigate("/diet");
      } else if (!data.isVerified) {
        setMessage({
          type: "error",
          text: "Email doğrulanmadı. Lütfen e-postanızı kontrol edin ve doğrulama işlemini tamamlayın."
        });
        throw new Error("Email doğrulanmadı. Lütfen e-postanızı kontrol edin ve doğrulama işlemini tamamlayın.");
      }
    } catch (error) {
      console.error('Login error:', error);
      if (!message.text) {
        setMessage({ type: "error", text: "Bir hata oluştu. Lütfen daha sonra tekrar deneyiniz." });
    }
  }
}

    return (
        <section className="container">
            <form className="form" onSubmit={handleSubmit}>
                <h1>Galwin Nutrition App</h1>
                <input className="inp" type="email" onChange={handleInput} placeholder="Email Girin" name="email" value={userCreds.email} required />
                <input className="inp" type="password" onChange={handleInput} placeholder="Şifre Girin" name="password" value={userCreds.password} required />
                <button className="btn">Giriş Yap</button>
                <div>
                    <p>Üye değil misiniz? <Link to="/register">Kayıt Olun</Link></p>
                    <p>Şifrenizi mi unuttunuz? <Link to="/forgotpassword">Tıklayın</Link></p>
                    <p className={message.type}>{message.text}</p>
                </div>
            </form>
        </section>
    );
}