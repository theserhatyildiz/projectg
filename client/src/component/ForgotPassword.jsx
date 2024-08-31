import { useState, useContext } from "react";
import { UserContext } from "../context/UserContext";
import { Link, useNavigate } from "react-router-dom";
import ClipLoader from "react-spinners/ClipLoader"; // Import ClipLoader

export default function ForgotPassword() {
    // ------------------Variables------------------
    const [userCreds, setUserCreds] = useState({
        email: "",
    });

    const [message, setMessage] = useState({
        type: "invisible-msg",
        text: "Dummy Msg"
    });

    const [loading, setLoading] = useState(false); // State for loading spinner
    const [color] = useState("#d73750"); // Color state for ClipLoader

    const navigate = useNavigate();
    const loggedData = useContext(UserContext);

    console.log(loggedData);

    // ------------------Functions------------------
    function handleInput(event) {
        setUserCreds((prevState) => {
            return { ...prevState, [event.target.name]: event.target.value };
        });
    }

    function handleSubmit(event) {
        event.preventDefault();
        console.log(userCreds);

        setLoading(true); // Show loading spinner

        // ------------------Sending the data to API------------------
        fetch("http://localhost:8000/forgotpassword", {
            method: "POST",
            body: JSON.stringify(userCreds),
            headers: {
                "Content-type": "application/json"
            }
        })
        .then(response => {
            setLoading(false); // Hide loading spinner

            if (response.status === 404) {
                setMessage({ type: "error", text: "Email Bulunamadı" });
            } else if (response.status === 403) {
                setMessage({ type: "error", text: "Hatalı Şifre" });
            } else if (response.status === 500) {
                setMessage({ type: "error", text: "Sunucu Hatası" });
            }

            setTimeout(() => {
                setMessage({ type: "invisible-msg", text: "Dummy Msg" });
            }, 10000);

            return response.json();
        })
        .then(data => {
            if (data.Status === "Success") {
                setMessage({ type: "success", text: "Şifre yenileme emaili gönderildi! Spam dosyanızı kontrol edin!" });
            }
        })
        .catch(err => {
            setLoading(false); // Hide loading spinner
            console.log(err);
        });
    }

    return (
        <section className="container">
            <form className="form" onSubmit={handleSubmit}>
                <h1>Şifre Yenileme</h1>
                <input
                    className="inp"
                    type="email"
                    onChange={handleInput}
                    placeholder="Email Girin"
                    name="email"
                    value={userCreds.email}
                    required
                />
                <button className="btn" type="submit">Yolla</button>
                <div className="forgotPass-p">
                    <p>Üye misiniz? <Link to="/login">Giriş Yapın</Link></p>
                    {loading && (
                        <div className="spinner-container-forgotPassword">
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
                </div>
            </form>
        </section>
    );
}