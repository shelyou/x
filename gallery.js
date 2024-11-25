// Data galeri (bisa disesuaikan)
const galleryData = [
    { imageUrl: 'path_to_image1.jpg', country: 'Country 1', description: 'Description of Country 1' },
    { imageUrl: 'path_to_image2.jpg', country: 'Country 2', description: 'Description of Country 2' },
    { imageUrl: 'path_to_image3.jpg', country: 'Country 3', description: 'Description of Country 3' },
    // Tambahkan item galeri lainnya sesuai kebutuhan
];

// Fungsi untuk membuat elemen galeri
function createGallery() {
    const galleryContainer = document.getElementById('galleryContainer');

    // Loop untuk membuat setiap item galeri
    galleryData.forEach(item => {
        const galleryItem = document.createElement('div');
        galleryItem.classList.add('gallery-item');
        galleryItem.onclick = () => flipImage(galleryItem);  // Panggil fungsi flip

        const front = document.createElement('div');
        front.classList.add('front');
        const img = document.createElement('img');
        img.src = item.imageUrl;
        img.alt = item.country;
        front.appendChild(img);

        const back = document.createElement('div');
        back.classList.add('back');
        back.onclick = (event) => handleBackClick(item.country, event);  // Panggil fungsi klik belakang
        back.textContent = item.description;

        galleryItem.appendChild(front);
        galleryItem.appendChild(back);
        galleryContainer.appendChild(galleryItem);
    });
}

// Inisialisasi galeri saat halaman dimuat
createGallery();
