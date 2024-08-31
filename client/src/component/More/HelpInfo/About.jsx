import { UserContext } from "../../../context/UserContext";
import { useContext, useState } from "react";
import Footer from "../../Footer";
import { Sheet } from 'react-modal-sheet';
import ClipLoader from "react-spinners/ClipLoader";
import { useNavigate} from "react-router-dom";

export default function About()
{
    const loggedData = useContext(UserContext);

    return(
        <section className="container about-container">
            <div className="about-list">
                <ul className="list-settings">
                    <div className="list-headings">
                        <span>Hakkımızda</span>
                    </div>
                    <div className="list-items">
                        <li>Privacy policy</li> 
                        <span>&gt;</span>
                    </div>
                    <div className="list-items">
                        <li>Terms & Conditions</li>
                        <span>&gt;</span>
                    </div>
                    <div className="list-items">
                        <li>Disclaimer</li>
                        <span>&gt;</span>
                    </div>
                    <div className="list-items">
                        <li>Version</li>
                        <span><strong>0.15.75</strong></span>
                    </div>
                    
                </ul>
            </div>

            <Footer />
           
        </section>
    );
}