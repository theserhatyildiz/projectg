import React, { useState } from 'react';
import Footer from "../../component/Footer";
import { Link} from "react-router-dom";
import { UserContext } from "../../context/UserContext";
import { useContext } from "react";

export default function More() {
    
    const loggedData = useContext(UserContext);
    

    return (
        <section className="container more-container">
            <div className="more-list-heading-group">
                <div>
                    <h2>Diğer</h2>
                </div>
                <div className="more-list">
                    <ul className="list-settings">

                        <div className="list-headings">
                            <span>Genel</span>
                        </div>

                        <div className="list-items">  
                        <li><Link to="/account">Hesap</Link></li>
                        <span><Link to="/account">&gt;</Link></span>
                        </div>

                        {/* <div className="list-items">  
                        <li><Link to="/profile">Profil</Link></li>
                        <span><Link to="/profile">&gt;</Link></span>
                        </div> */}


                        <div className="list-headings">
                            <span>Bilgi & Yardım</span>
                        </div>

                        <div className="list-items">
                        <li>Sıkça Sorulan Sorular</li>
                        <span>&gt;</span>
                        </div>
                        
                        <div className="list-items">
                        <li><Link to="/about">Hakkımızda</Link></li>
                        <span><Link to="/about">&gt;</Link></span>
                        </div>
                
                    </ul>
                </div>
            </div>
            <Footer />
        </section>
    );
}