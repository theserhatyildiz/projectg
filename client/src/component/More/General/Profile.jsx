import { UserContext } from "../../../context/UserContext";
import { useContext, useState } from "react";
import Footer from "../../Footer";
import { Sheet } from 'react-modal-sheet';
import ClipLoader from "react-spinners/ClipLoader";
import { useNavigate} from "react-router-dom";

export default function Profile()
{
    const loggedData = useContext(UserContext);

    return(
        <section className="container profile-container">
            <div className="profile-list">
                <ul className="list-settings">
                    <div className="list-headings">
                        <span>Hesap</span>
                    </div>
                    <div className="list-items">
                        <li>Kullanıcı Adı</li>
                        
                    </div>
                    <div className="list-items">
                        <li>E-posta</li>
                    </div>
                    
                </ul>
            </div>

            <Footer />
           
        </section>
    );
}
        
    