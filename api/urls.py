from django.urls import path
from .views import *
from .admin_views import *
from .chatbot_views import *

urlpatterns = [

    #USERS
    path("user_signup/", user_signup, name="user_signup"),
    path("user_login/", user_login, name="user_login"),
    path("check_user/", check_user, name="check_user"),
    path('send_email_otp/', send_email_otp, name="send_email_otp"),
    path('send_sms_otp/', send_sms_otp, name="send_sms_otp"),
    path('verify_email_otp/', verify_email_otp, name="verify_email_otp"),
    path('verify_sms_otp/', verify_sms_otp, name="verify_sms_otp"),
    path("google_login/", google_login, name="google_login"),
    path("forgot_password/", forgot_password, name="forgot_password"),
    path("verify_reset_token/", verify_reset_token, name="verify_reset_token"),
    path("reset_password/", reset_password, name="reset_password"),
    path("request_appointment/", request_appointment, name="request_appointment"),
    path("contact-us/", submit_contact_us, name="submit_contact_us"),
    path("increment/<str:product_id>/", increment_product_view, name="increment"),
    path('subscribe/',subscribe_user,name="subscribe_user"),

    #ADMIN
    path("admin_signup/", admin_signup, name="admin_signup"),
    path("admin_login/",admin_login, name="admin_login"),
    path("google_admin_login/", google_admin_login, name="google_admin_login"),
    path("get-admin-products/", get_admin_products, name="get_admin_products"),
    path("appointments/", get_appointments, name="get_admin_appointments"),
    path("appointments/<str:appointment_id>/read/", mark_appointment_as_read, name="mark_as_read"),
    path("appointments/<str:appointment_id>/unread/", mark_appointment_as_unread, name="mark_as_unread"),
    path("appointments/<str:appointment_id>/delete/", delete_appointment, name="delete_appointment"),

    #SUPERADMIN
    path("superadmin_signup/", superadmin_signup, name="superadmin_signup"),
    path("superadmin_login/",superadmin_login, name="superadmin_login"),
    path("google_superadmin_login/", google_superadmin_login, name="google_superadmin_login"),
    path('get-all-products/',get_all_products, name='get_all_products'),
    path('get-superadmin-products/',get_superadmin_products, name='get_superadmin_products'),
    path("review-product/<str:product_id>/", review_product, name="review_product"),
    path('get_admin_details/',get_admin_details, name="get_admin_details"),
    path("contact-us/all/", get_all_contact_us, name="get_all_contact_us"),
    path("contact-us/<str:message_id>/delete/", delete_contact_message, name="delete_contact_message"),
    path("user_management/", user_management, name="user_management"),
    path("get_subscribers", get_subscribers, name="get_subscribers"),
    path("send_newsletter/",send_newsletter,name="send_newsletter"),

    #COMMON
    path("get_profile/<str:user_id>/", get_profile, name="get_profile"),
    path("edit_profile/<str:user_id>/", edit_profile, name="edit_profile"),

    #PRODUCTS
    path("post_product/", post_product, name="post_product"),
    path('get_product/', get_products, name="get_product"),
    path('published-products/',published_products, name="published_products"), #Publish Products
    path('edit_product/<str:product_id>/', edit_product, name='edit_product'),
    path('delete_product/<str:product_id>/', delete_product, name='delete_product'),
    path("get_product/<str:product_id>/", get_product, name="get_product"), #To view any of any the product
    path('toggle_bookmark/<str:product_id>/', toggle_bookmark, name='toggle_bookmark'),
    path('premium_product/<str:product_id>/', premium_product, name="premium_product" ),
    path('get_premium_products/',get_premium_products,name="get_premium_products"),
    path('get-products-by-category/', get_products_by_category, name='get_products_by_category'),

    #CHATBOT
    path("chat/", chatbot_view, name="chatbot"),

    #Notifications
    path("admin-notification/", get_admin_notification, name="get_notifications"),
    path("superadmin-notification/", get_superadmin_notification, name="get_notifications"),
]
