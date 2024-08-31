import { useNavigate, Link } from "react-router-dom";
import { UserContext } from "../context/UserContext";
import { useContext } from "react";


export default function Footer(){

 // ------------------Variables------------------

 const loggedData = useContext(UserContext);

 const navigate = useNavigate();


 // ------------------Functions------------------

 function logout()
 {
     localStorage.removeItem("app-user");
     loggedData.setLoggedUser(null);
     navigate("/login");

 }



 return(
     <div>
          <ul className="footer">
             <Link to="/diet"><li>Diyet</li></Link>
             <Link to="/search"><li>Arama</li></Link>
             <Link to="/createfood"><li>Oluştur</li></Link>
             <Link to="/weight"><li>Kilo</li></Link>
             <Link to="/more"><li>Diğer</li></Link>
         </ul>
     </div>
 )
}
