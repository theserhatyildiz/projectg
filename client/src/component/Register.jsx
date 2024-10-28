import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import ClipLoader from "react-spinners/ClipLoader";

export default function Register() {
    const [userDetails, setUserDetails] = useState({
        name: "",
        email: "",
        password: "",
        passwordConfirm: "",
    });

    const [message, setMessage] = useState({
        type: "invisible-msg",
        text: "Dummy Msg"
    });

    const [loading, setLoading] = useState(false);
    const [csrfToken, setCsrfToken] = useState(""); // State to store CSRF token

    const color = "#d73750"; // Color state for ClipLoader

    useEffect(() => {
        fetchCsrfToken(); // Fetch CSRF token on component mount
    }, []);

    async function fetchCsrfToken() {
        try {
            const response = await fetch("http://localhost:8000/csrf-token", { credentials: 'include' });
            const { csrfToken } = await response.json();
            console.log('CSRF Token fetched:', csrfToken);
            if (csrfToken) {
                setCsrfToken(csrfToken);
                document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; HttpOnly; SameSite=Strict; path=/`;
                console.log('CSRF Token stored in cookie:',csrfToken);
            }
        } catch (error) {
            console.error('Error fetching CSRF token:', error);
        }
    }

    function handleInput(event) {
        setUserDetails((prevState) => ({
            ...prevState,
            [event.target.name]: event.target.value
        }));
    }

    async function handleSubmit(event) {
        event.preventDefault();
        setLoading(true);

        // Check if passwords match
        if (userDetails.password !== userDetails.passwordConfirm) {
            setLoading(false);
            setMessage({ type: "error", text: "Şifreler eşleşmiyor!" });
            return;
        }

        try {
            const response = await fetch("http://localhost:8000/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "CSRF-Token": csrfToken // Include CSRF token in headers
                },
                body: JSON.stringify(userDetails),
                credentials: 'include'
            });

            const data = await response.json();
            setLoading(false);

            if (response.ok) {
                setMessage({ type: "success", text: 'Üyelik oluşturuldu! Lütfen e-posta adresinizi doğrulamak için e-postanızı kontrol edin.' });
                setUserDetails({
                    name: "",
                    email: "",
                    password: "",
                    passwordConfirm: "",
                });
                setTimeout(() => {
                    setMessage({ type: "invisible-msg", text: "Dummy Msg" });
                }, 5000);
            } else {
                setMessage({ type: "error", text: data.message });
            }
        } catch (error) {
            console.error('Registration error:', error);
            setLoading(false);
            setMessage({ type: "error", text: "Bir hata oluştu. Lütfen daha sonra tekrar deneyiniz." });
        }
    }

    return (
        <section className="container">
            <form className="form" onSubmit={handleSubmit}>

                <h1>Galwin Nutrition App</h1>

                <input className="inp" type="text" onChange={handleInput} placeholder="Kullanıcı adı girin" name="name" value={userDetails.name} required />
                <input className="inp" type="email" onChange={handleInput} placeholder="Email girin" name="email" value={userDetails.email} required />
                <input className="inp" type="password" minLength={11} onChange={handleInput} placeholder="En az 11 karakter olmalı, harf ve rakam içermeli" name="password" value={userDetails.password} required />
                <input className="inp" type="password" minLength={11} onChange={handleInput} placeholder="Şifre tekrar" name="passwordConfirm" value={userDetails.passwordConfirm} required />

                <button className="btn" type="submit" disabled={loading}>
                    Kayıt Ol
                </button>

                <p>Üye misiniz? <Link to="/login">Giriş Yap</Link></p>

                {loading && (
                    <div className="spinner-container-register">
                        <ClipLoader
                            color={color}
                            loading={loading}
                            size={25}
                            aria-label="Loading Spinner"
                            data-testid="loader"
                        />
                    </div>
                )}

                <p className={message.type}>{message.text}</p>

            </form>
        </section>
    );
}