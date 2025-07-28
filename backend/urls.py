from django.contrib import admin
from django.urls import path
from . import views  # This line fixes the error

from .views import logout_view, home_view

urlpatterns = [
    path('admin/', admin.site.urls),
        path('', home_view, name='home') , 
        path('cart/', views.cart_view, name='cart'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('reset-password/', views.password_reset_view, name='password_reset'),
    path('search/', views.searchproduct_view, name='searchproduct'),
        path('account/', views.account_view, name='account'),
            path('edit-profile/', views.edit_profile_view, name='editprofile'),
                # path('category/', views.category_view, name='category'),
                    path('customize/<int:product_id>/', views.customize_product_view, name='customize'),

                    path('cart/', views.cart_view, name='cart'),
                        path('logout/', logout_view, name='logout'),
                            path('placeorder/', views.placeorder_view, name='placeorder'),
                                path('wishlist/', views.wishlist_view, name='wishlist'),
                                    path('beforecart/', views.beforecart_view, name='beforecart'),
                                        path('reset-code/', views.reset_code_view, name='reset_code'),
                                        path('set-new-password/', views.set_new_password_view, name='set_new_password'),
                                            path('save/', views.save_view, name='save'),
                                                path('add-to-save/', views.add_to_save, name='add_to_save'),
                                                    # path('contact/', views.contact_view, name='contact'),
                                                        path('upload-profile-picture/', views.upload_profile_picture, name='upload_profile_picture'),
                                                            path('send-contact-email/', views.send_contact_email, name='send_contact_email'),
                                                                path('save-payment/', views.save_payment_details, name='save_payment'),
    path('searchview/', views.search_view, name='search'),
    path('submit-review/', views.submit_review, name='submit_review'),
    path('khalti/initiate/', views.initiate_khalti_payment, name='khalti_initiate'),

 path('initiate-khalti/',views. initiate_khalti_payment, name='initiate_khalti'),
    path('save-payment-details/', views.save_payment_details, name='save_payment'),
    path('payment-success/', views.payment_success_view, name='payment_success'),
        path('send-cod-email/', views.send_cod_email, name='send_cod_email'),

    # Stripe payment endpoints
    path('stripe-create-payment-intent/', views.stripe_create_payment_intent, name='stripe_create_payment_intent'),
    path('stripe-confirm-payment/', views.stripe_confirm_payment, name='stripe_confirm_payment'),

    # Review submission
    path('submit-review/', views.submit_review, name='submit_review'),
    
    # Search functionality
    path('searchview/', views.search_view, name='search'),
    
    # Password Security API endpoints
    path('check-password-strength/', views.check_password_strength, name='check_password_strength'),
    path('check-password-reuse/', views.check_password_reuse, name='check_password_reuse'),

]
