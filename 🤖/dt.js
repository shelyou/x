// Array berisi item galeri
const galleryItems = [
{ imgSrc: "IMG_8514.png", alt: "USA", label: "USA" },
{ imgSrc: "IMG_8514.png", alt: "Russia", label: "Russia" },
{ imgSrc: "IMG_8514.png", alt: "China", label: "China" },
{ imgSrc: "IMG_8514.png", alt: "India", label: "India" },
{ imgSrc: "IMG_8514.png", alt: "EU", label: "EU" },
{ imgSrc: "IMG_8514.png", alt: "Japan", label: "Japan" },
{ imgSrc: "IMG_8514.png", alt: "S. Korea", label: "S. Korea" },
{ imgSrc: "IMG_8514.png", alt: "Canada", label: "Canada" },
{ imgSrc: "IMG_8514.png", alt: "Brazil", label: "Brazil" },
{ imgSrc: "IMG_8514.png", alt: "Indonesia", label: "Indonesia" },
{ imgSrc: "IMG_8514.png", alt: "Mexico", label: "Mexico" },
{ imgSrc: "IMG_8514.png", alt: "UK", label: "UK" },
{ imgSrc: "IMG_8514.png", alt: "France", label: "France" },
{ imgSrc: "IMG_8514.png", alt: "Australia", label: "Australia" },
{ imgSrc: "IMG_8514.png", alt: "Turkey", label: "Turkey" },
{ imgSrc: "IMG_8514.png", alt: "Pakistan", label: "Pakistan" },
{ imgSrc: "IMG_8514.png", alt: "Nigeria", label: "Nigeria" },
{ imgSrc: "IMG_8514.png", alt: "UAE", label: "UAE" },
{ imgSrc: "IMG_8514.png", alt: "Vietnam", label: "Vietnam" },
{ imgSrc: "IMG_8514.png", alt: "Thailand", label: "Thailand" },
{ imgSrc: "IMG_8514.png", alt: "Philippines", label: "Philippines" },
{ imgSrc: "IMG_8514.png", alt: "Argentina", label: "Argentina" },
{ imgSrc: "IMG_8514.png", alt: "S. Africa", label: "S. Africa" },
{ imgSrc: "IMG_8514.png", alt: "Ethiopia", label: "Ethiopia" },
{ imgSrc: "IMG_8514.png", alt: "Poland", label: "Poland" },
{ imgSrc: "IMG_8514.png", alt: "Romania", label: "Romania" },
{ imgSrc: "IMG_8514.png", alt: "Israel", label: "Israel" },
{ imgSrc: "IMG_8514.png", alt: "Sweden", label: "Sweden" },
{ imgSrc: "IMG_8514.png", alt: "Finland", label: "Finland" },
{ imgSrc: "IMG_8514.png", alt: "Norway", label: "Norway" },
{ imgSrc: "IMG_8514.png", alt: "Denmark", label: "Denmark" },
{ imgSrc: "IMG_8514.png", alt: "Switzerland", label: "Switzerland" },
{ imgSrc: "IMG_8514.png", alt: "Hungary", label: "Hungary" },
{ imgSrc: "IMG_8514.png", alt: "Czech Rep.", label: "Czech Rep." },
{ imgSrc: "IMG_8514.png", alt: "Croatia", label: "Croatia" },
{ imgSrc: "IMG_8514.png", alt: "Slovenia", label: "Slovenia" },
{ imgSrc: "IMG_8514.png", alt: "Serbia", label: "Serbia" },
{ imgSrc: "IMG_8514.png", alt: "Bosnia", label: "Bosnia" },
{ imgSrc: "IMG_8514.png", alt: "Albania", label: "Albania" },
{ imgSrc: "IMG_8514.png", alt: "Kosovo", label: "Kosovo" },
{ imgSrc: "IMG_8514.png", alt: "Georgia", label: "Georgia" },
{ imgSrc: "IMG_8514.png", alt: "Armenia", label: "Armenia" },
{ imgSrc: "IMG_8514.png", alt: "Azerbaijan", label: "Azerbaijan" },
{ imgSrc: "IMG_8514.png", alt: "Moldova", label: "Moldova" },
{ imgSrc: "IMG_8514.png", alt: "Belarus", label: "Belarus" },
{ imgSrc: "IMG_8514.png", alt: "Uzbekistan", label: "Uzbekistan" },
{ imgSrc: "IMG_8514.png", alt: "Kyrgyzstan", label: "Kyrgyzstan" },
{ imgSrc: "IMG_8514.png", alt: "Turkmenistan", label: "Turkmenistan" },
{ imgSrc: "IMG_8514.png", alt: "Tajikistan", label: "Tajikistan" },
{ imgSrc: "IMG_8514.png", alt: "Sri Lanka", label: "Sri Lanka" },
{ imgSrc: "IMG_8514.png", alt: "Nepal", label: "Nepal" },
{ imgSrc: "IMG_8514.png", alt: "Bangladesh", label: "Bangladesh" },
{ imgSrc: "IMG_8514.png", alt: "Myanmar", label: "Myanmar" },
{ imgSrc: "IMG_8514.png", alt: "Jordan", label: "Jordan" },
{ imgSrc: "IMG_8514.png", alt: "Kuwait", label: "Kuwait" },
{ imgSrc: "IMG_8514.png", alt: "Qatar", label: "Qatar" },
{ imgSrc: "IMG_8514.png", alt: "Bahrain", label: "Bahrain" },
{ imgSrc: "IMG_8514.png", alt: "Oman", label: "Oman" },
{ imgSrc: "IMG_8514.png", alt: "Lebanon", label: "Lebanon" },
{ imgSrc: "IMG_8514.png", alt: "Iraq", label: "Iraq" },
{ imgSrc: "IMG_8514.png", alt: "Yemen", label: "Yemen" },
{ imgSrc: "IMG_8514.png", alt: "Libya", label: "Libya" },
{ imgSrc: "IMG_8514.png", alt: "Sudan", label: "Sudan" },
{ imgSrc: "IMG_8514.png", alt: "Somalia", label: "Somalia" },
{ imgSrc: "IMG_8514.png", alt: "Chad", label: "Chad" },
{ imgSrc: "IMG_8514.png", alt: "CAR", label: "CAR" },
{ imgSrc: "IMG_8514.png", alt: "Cameroon", label: "Cameroon" },
{ imgSrc: "IMG_8514.png", alt: "Gabon", label: "Gabon" },
{ imgSrc: "IMG_8514.png", alt: "Congo", label: "Congo" },
{ imgSrc: "IMG_8514.png", alt: "Seychelles", label: "Seychelles" },
{ imgSrc: "IMG_8514.png", alt: "Mauritius", label: "Mauritius" },
{ imgSrc: "IMG_8514.png", alt: "Madagascar", label: "Madagascar" },
{ imgSrc: "IMG_8514.png", alt: "Mozambique", label: "Mozambique" },
{ imgSrc: "IMG_8514.png", alt: "Angola", label: "Angola" },
{ imgSrc: "IMG_8514.png", alt: "Zambia", label: "Zambia" },
{ imgSrc: "IMG_8514.png", alt: "Burundi", label: "Burundi" },
{ imgSrc: "IMG_8514.png", alt: "Rwanda", label: "Rwanda" },
{ imgSrc: "IMG_8514.png", alt: "Botswana", label: "Botswana" },
{ imgSrc: "IMG_8514.png", alt: "Namibia", label: "Namibia" },
{ imgSrc: "IMG_8514.png", alt: "Malawi", label: "Malawi" },
{ imgSrc: "IMG_8514.png", alt: "Liberia", label: "Liberia" },
{ imgSrc: "IMG_8514.png", alt: "Sierra Leone", label: "Sierra Leone" },
{ imgSrc: "IMG_8514.png", alt: "Burkina Faso", label: "Burkina Faso" },
{ imgSrc: "IMG_8514.png", alt: "Mali", label: "Mali" },
{ imgSrc: "IMG_8514.png", alt: "Ghana", label: "Ghana" },
{ imgSrc: "IMG_8514.png", alt: "Ivory Coast", label: "Ivory Coast" },
{ imgSrc: "IMG_8514.png", alt: "Togo", label: "Togo" },
{ imgSrc: "IMG_8514.png", alt: "Benin", label: "Benin" },
{ imgSrc: "IMG_8514.png", alt: "Niger", label: "Niger" },
{ imgSrc: "IMG_8514.png", alt: "Mauritania", label: "Mauritania" },
{ imgSrc: "IMG_8514.png", alt: "Eswatini", label: "Eswatini" },
{ imgSrc: "IMG_8514.png", alt: "Lesotho", label: "Lesotho" },
{ imgSrc: "IMG_8514.png", alt: "Guinea", label: "Guinea" },
{ imgSrc: "IMG_8514.png", alt: "Guinea-Bissau", label: "Guinea-Bissau" },
{ imgSrc: "IMG_8514.png", alt: "Comoros", label: "Comoros" },
{ imgSrc: "IMG_8514.png", alt: "Cape Verde", label: "Cape Verde" },
{ imgSrc: "IMG_8514.png", alt: "São Tomé", label: "São Tomé" },
{ imgSrc: "IMG_8514.png", alt: "Timor-Leste", label: "Timor-Leste" },
{ imgSrc: "IMG_8514.png", alt: "Solomon Is.", label: "Solomon Is." },
{ imgSrc: "IMG_8514.png", alt: "Vanuatu", label: "Vanuatu" }
{ imgSrc: "IMG_8514.png", alt: "Fiji", label: "Fiji" },
{ imgSrc: "IMG_8514.png", alt: "Tonga", label: "Tonga" },
{ imgSrc: "IMG_8514.png", alt: "Samoa", label: "Samoa" },
{ imgSrc: "IMG_8514.png", alt: "Palau", label: "Palau" },
{ imgSrc: "IMG_8514.png", alt: "Micronesia", label: "Micronesia" },
{ imgSrc: "IMG_8514.png", alt: "Marshall Is.", label: "Marshall Is." },
{ imgSrc: "IMG_8514.png", alt: "Nauru", label: "Nauru" },
{ imgSrc: "IMG_8514.png", alt: "Kiribati", label: "Kiribati" },
{ imgSrc: "IMG_8514.png", alt: "Tuvalu", label: "Tuvalu" },
{ imgSrc: "IMG_8514.png", alt: "Nicaragua", label: "Nicaragua" },
{ imgSrc: "IMG_8514.png", alt: "Honduras", label: "Honduras" },
{ imgSrc: "IMG_8514.png", alt: "El Salvador", label: "El Salvador" },
{ imgSrc: "IMG_8514.png", alt: "Costa Rica", label: "Costa Rica" },
{ imgSrc: "IMG_8514.png", alt: "Panama", label: "Panama" },
{ imgSrc: "IMG_8514.png", alt: "Guatemala", label: "Guatemala" },
{ imgSrc: "IMG_8514.png", alt: "Belize", label: "Belize" },
{ imgSrc: "IMG_8514.png", alt: "Saint Lucia", label: "Saint Lucia" },
{ imgSrc: "IMG_8514.png", alt: "Saint Vincent", label: "Saint Vincent" },
{ imgSrc: "IMG_8514.png", alt: "Barbados", label: "Barbados" },
{ imgSrc: "IMG_8514.png", alt: "Grenada", label: "Grenada" },
{ imgSrc: "IMG_8514.png", alt: "Trinidad", label: "Trinidad" },
{ imgSrc: "IMG_8514.png", alt: "Jamaica", label: "Jamaica" },
{ imgSrc: "IMG_8514.png", alt: "Dominica", label: "Dominica" },
{ imgSrc: "IMG_8514.png", alt: "St. Kitts", label: "St. Kitts" },
{ imgSrc: "IMG_8514.png", alt: "Antigua", label: "Antigua" },
{ imgSrc: "IMG_8514.png", alt: "Saint Pierre", label: "Saint Pierre" },
{ imgSrc: "IMG_8514.png", alt: "Bermuda", label: "Bermuda" },
{ imgSrc: "IMG_8514.png", alt: "Cayman Is.", label: "Cayman Is." },
{ imgSrc: "IMG_8514.png", alt: "BVI", label: "BVI" },
{ imgSrc: "IMG_8514.png", alt: "Anguilla", label: "Anguilla" },
{ imgSrc: "IMG_8514.png", alt: "Montserrat", label: "Montserrat" },
{ imgSrc: "IMG_8514.png", alt: "Turks & Caicos", label: "Turks & Caicos" },
{ imgSrc: "IMG_8514.png", alt: "Saint Barthelemy", label: "Saint Barthelemy" },
{ imgSrc: "IMG_8514.png", alt: "Saint Martin", label: "Saint Martin" },
{ imgSrc: "IMG_8514.png", alt: "Guadeloupe", label: "Guadeloupe" },
{ imgSrc: "IMG_8514.png", alt: "Martinique", label: "Martinique" },
{ imgSrc: "IMG_8514.png", alt: "French Guyana", label: "French Guyana" },
{ imgSrc: "IMG_8514.png", alt: "Reunion", label: "Reunion" },
{ imgSrc: "IMG_8514.png", alt: "Mayotte", label: "Mayotte" },
{ imgSrc: "IMG_8514.png", alt: "New Caledonia", label: "New Caledonia" },
{ imgSrc: "IMG_8514.png", alt: "Polynesia", label: "Polynesia" },
{ imgSrc: "IMG_8514.png", alt: "Wallis & Futuna", label: "Wallis & Futuna" },
{ imgSrc: "IMG_8514.png", alt: "Cook Is.", label: "Cook Is." },
{ imgSrc: "IMG_8514.png", alt: "Niue", label: "Niue" },
{ imgSrc: "IMG_8514.png", alt: "A. Samoa", label: "A. Samoa" },
{ imgSrc: "IMG_8514.png", alt: "Guam", label: "Guam" },
{ imgSrc: "IMG_8514.png", alt: "N. Mariana Is.", label: "N. Mariana Is." },
{ imgSrc: "IMG_8514.png", alt: "Federated States", label: "Federated States" },
{ imgSrc: "IMG_8514.png", alt: "Palau", label: "Palau" },
{ imgSrc: "IMG_8514.png", alt: "Micronesia", label: "Micronesia" },
{ imgSrc: "IMG_8514.png", alt: "Marshall Is.", label: "Marshall Is." },
{ imgSrc: "IMG_8514.png", alt: "Nauru", label: "Nauru" }
];

// Fungsi untuk membuat elemen galeri
function createGalleryItem(item) {
    const galleryItem = document.createElement("div");
    galleryItem.className = "gallery-item";
    galleryItem.setAttribute("onclick", "flipImage(this)");

    const galleryItemInner = document.createElement("div");
    galleryItemInner.className = "gallery-item-inner";

    const galleryFront = document.createElement("div");
    galleryFront.className = "gallery-front";
    const img = document.createElement("img");
    img.src = item.imgSrc;
    img.alt = item.alt;
    galleryFront.appendChild(img);

    const galleryBack = document.createElement("div");
    galleryBack.className = "gallery-back";
    galleryBack.textContent = item.label;
    galleryBack.setAttribute(
        "onclick",
        `handleBackClick('${item.label}', event); checkStorageAndDownload('${item.label}')`
    );

    galleryItemInner.appendChild(galleryFront);
    galleryItemInner.appendChild(galleryBack);
    galleryItem.appendChild(galleryItemInner);

    return galleryItem;
}

// Fungsi untuk membangun galeri
function buildGallery() {
    const galleryContainer = document.querySelector(".gallery-container .gallery");

    if (!galleryContainer) {
        console.error("Gallery container not found!");
        return;
    }

    galleryItems.forEach((item) => {
        const galleryItem = createGalleryItem(item);
        galleryContainer.appendChild(galleryItem);
    });
}

// Fungsi untuk membalik gambar
function flipImage(item) {
    const allItems = document.querySelectorAll('.gallery-item');
    allItems.forEach((el) => {
        if (el !== item) {
            el.classList.remove('flipped');
        }
    });
    item.classList.toggle('flipped');
}

// Fungsi untuk menangani klik di luar gambar
function handleOutsideClick(event) {
    const galleryItems = document.querySelectorAll('.gallery-item');
    galleryItems.forEach((item) => {
        if (!item.contains(event.target)) {
            item.classList.remove('flipped');
        }
    });
}

// Fungsi untuk menangani klik pada bagian belakang gambar
function handleBackClick(country, event) {
    event.stopPropagation();
    alert('You clicked on the back of the image for ' + country);
}

// Daftarkan event listener saat halaman selesai dimuat
document.addEventListener("DOMContentLoaded", buildGallery);
document.addEventListener('click', handleOutsideClick);
