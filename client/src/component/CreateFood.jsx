import { UserContext } from "../context/UserContext";
import { useContext } from "react";
import { useState,useEffect } from "react";
import Header from './Header';
import Footer from "./Footer";

export default function CreateFood() {
  // ------------------Variables------------------

  const loggedData = useContext(UserContext);

  const [foodDetails, setFoodDetails] = useState({
    NameTr: "",
    Calorie: "",
    Protein: "",
    Carbohydrate: "",
    Fat: "",
    Fiber: "",
    userId: loggedData.loggedUser.userid 
  });

  const [message, setMessage] = useState({ 
    type: "", 
    text: "" 
  });

  const [csrfToken, setCsrfToken] = useState('');

  useEffect(() => {
    async function fetchCsrfToken() {
        try {
            const response = await fetch("http://localhost:8000/csrf-token", { credentials: 'include' });
            const { csrfToken } = await response.json();
            console.log('CSRF Token fetched:', csrfToken);
            if (csrfToken) {
                setCsrfToken(csrfToken);
                document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; SameSite=Strict; path=/`;
                console.log('CSRF Token stored in cookie:', csrfToken);
            }
        } catch (error) {
            console.error('Error fetching CSRF token:', error);
        }
    }

    fetchCsrfToken();
}, []);

  // ------------------Functions------------------

  function handleInput(event) {
    setFoodDetails((prevState) => {
      return { ...prevState, [event.target.name]: event.target.value, userId: loggedData.loggedUser.userid};
    });
  }


  function handleSubmit(event) {
    event.preventDefault();
    console.log(foodDetails);



    // ------------------Sending the data to API------------------

    fetch("http://localhost:8000/foods",{
        method:"POST",
        body:JSON.stringify(foodDetails),
        headers:{
            "Authorization":`Bearer ${loggedData.loggedUser.token}`,
            "Content-Type":"application/json",
            "csrf-token": csrfToken
        },
        credentials: 'include'
    })
    .then((response) => {
      if (response.status === 201) {
          setMessage({ type: "success", text: "Yiyecek oluşturuldu!" });
          
      } else {
          setMessage({ type: "error", text: "Bir hata oluştu!" });
      }

      setTimeout(() => {
          setMessage({ type: "", text: "" })
      }, 2000);
      return response.json();
  })
  .then((data) => {
      console.log(data)
  })
  .catch((err) => {
      console.log(err)
  });
}


 
  return (
   
    <section className="container createfood-container">
         <Header/>
         <Footer/>
      <form className="form" onSubmit={handleSubmit}>
        <h1>Yeni Yiyecek</h1>
        <div>
          <span>100g besin değerlerini girin.</span>
        </div>

        <div className="create-food-info">
          <div className="name-calorie-form">
            <h2 className="name-form">İsim: </h2>
            <input
              type="text"
              maxLength={50} 
              onChange={handleInput}
              className="inp-name"
              placeholder="Gerekli"
              name="NameTr"
              value={foodDetails.NameTr}
              required
            />

            <h2 className="calorie-form">Kalori: </h2>
            <input
              type="number"
              onInput={(e) => {
                if (e.target.value.length > 6) {
                  e.target.value = e.target.value.slice(0, 6);
                }
              }} 
              onChange={handleInput}
              className="inp-cal"
              placeholder="Gerekli"
              name="Calorie"
              value={foodDetails.Calorie}
              required
            />
          </div>

          <div className="nutrient">
            <p className="n-title">Pro</p>
            <input
              type="number"
              onInput={(e) => {
                if (e.target.value.length > 6) {
                  e.target.value = e.target.value.slice(0, 6);
                }
              }} 
              onChange={handleInput}
              className="inp-create"
              placeholder="Gerekli"
              name="Protein"
              value={foodDetails.Protein}
              required
            />
          </div>

          <div className="nutrient">
            <p className="n-title">Karb</p>
            <input
              type="number"
              onInput={(e) => {
                if (e.target.value.length > 6) {
                  e.target.value = e.target.value.slice(0, 6);
                }
              }}
              onChange={handleInput}
              className="inp-create"
              placeholder="Gerekli"
              name="Carbohydrate"
              value={foodDetails.Carbohydrate}
              required
            />
          </div>

          <div className="nutrient">
            <p className="n-title">Yağ</p>
            <input
              type="number"
              onInput={(e) => {
                if (e.target.value.length > 6) {
                  e.target.value = e.target.value.slice(0, 6);
                }
              }}
              onChange={handleInput}
              className="inp-create"
              placeholder="Gerekli"
              name="Fat"
              value={foodDetails.Fat}
              required
            />
          </div>

          <div className="nutrient">
            <p className="n-title">Lif</p>
            <input
              type="number"
              onInput={(e) => {
                if (e.target.value.length > 6) {
                  e.target.value = e.target.value.slice(0, 6);
                }
              }}
              onChange={handleInput}
              className="inp-create"
              placeholder="Gerekli"
              name="Fiber"
              value={foodDetails.Fiber}
              required
            />
          </div>

          <button className="btn-add">Oluştur</button>
        </div>
        <p className={message.type}>{message.text}</p>
      </form>
    </section>
  );
}