// pubspec.yaml
name: crave
description: A local business discovery app connecting users with bars, restaurants, and activities
publish_to: 'none'
version: 1.0.0+1

environment:
  sdk: '>=3.0.0 <4.0.0'
  flutter: ">=3.10.0"

dependencies:
  flutter:
    sdk: flutter
  cupertino_icons: ^1.0.2
  
  # State Management
  provider: ^6.1.2
  riverpod: ^2.4.9
  flutter_riverpod: ^2.4.9
  
  # UI & Navigation
  go_router: ^12.1.3
  cached_network_image: ^3.3.0
  shimmer: ^3.0.0
  lottie: ^2.7.0
  
  # Location & Maps
  geolocator: ^10.1.0
  geocoding: ^2.1.1
  google_maps_flutter: ^2.5.0
  permission_handler: ^11.1.0
  
  # Networking & Data
  dio: ^5.3.4
  retrofit: ^4.0.3
  json_annotation: ^4.8.1
  
  # Storage
  shared_preferences: ^2.2.2
  hive: ^2.2.3
  hive_flutter: ^1.1.0
  
  # Authentication
  firebase_core: ^2.24.2
  firebase_auth: ^4.15.3
  google_sign_in: ^6.1.6
  
  # Analytics & Notifications
  firebase_analytics: ^10.7.4
  firebase_messaging: ^14.7.10
  flutter_local_notifications: ^16.3.2
  
  # Image & Media
  image_picker: ^1.0.4
  video_player: ^2.8.1
  photo_view: ^0.14.0
  
  # Utils
  intl: ^0.19.0
  uuid: ^4.2.1
  url_launcher: ^6.2.2

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^3.0.0
  
  # Code Generation
  build_runner: ^2.4.7
  json_serializable: ^6.7.1
  retrofit_generator: ^8.0.4
  hive_generator: ^2.0.1

flutter:
  uses-material-design: true
  assets:
    - assets/images/
    - assets/animations/
    - assets/icons/

---

// lib/main.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:firebase_core/firebase_core.dart';
import 'core/config/app_config.dart';
import 'core/router/app_router.dart';
import 'core/theme/app_theme.dart';
import 'core/services/notification_service.dart';
import 'core/services/location_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  await Firebase.initializeApp();
  await AppConfig.initialize();
  await NotificationService.initialize();
  await LocationService.initialize();
  
  runApp(const ProviderScope(child: CraveApp()));
}

class CraveApp extends ConsumerWidget {
  const CraveApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(appRouterProvider);
    
    return MaterialApp.router(
      title: 'Crave',
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      routerConfig: router,
      debugShowCheckedModeBanner: false,
    );
  }
}

---

// lib/core/config/app_config.dart
class AppConfig {
  static const String appName = 'Crave';
  static const String apiBaseUrl = 'https://api.crave.app/v1';
  static const String googleMapsApiKey = 'YOUR_GOOGLE_MAPS_API_KEY';
  static const int searchRadius = 10; // km
  static const int notificationRadius = 5; // km
  
  static Future<void> initialize() async {
    // Initialize any required services
  }
}

---

// lib/core/theme/app_theme.dart
import 'package:flutter/material.dart';

class AppTheme {
  static const Color primaryColor = Color(0xFF6C63FF);
  static const Color secondaryColor = Color(0xFFFF6B9D);
  static const Color accentColor = Color(0xFFFFC107);
  static const Color backgroundColor = Color(0xFFF8F9FA);
  static const Color surfaceColor = Color(0xFFFFFFFF);
  static const Color errorColor = Color(0xFFE74C3C);

  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      colorScheme: ColorScheme.fromSeed(
        seedColor: primaryColor,
        brightness: Brightness.light,
        background: backgroundColor,
        surface: surfaceColor,
        error: errorColor,
      ),
      appBarTheme: const AppBarTheme(
        elevation: 0,
        centerTitle: true,
        backgroundColor: surfaceColor,
        foregroundColor: Colors.black87,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: primaryColor,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
    );
  }

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      colorScheme: ColorScheme.fromSeed(
        seedColor: primaryColor,
        brightness: Brightness.dark,
      ),
    );
  }
}

---

// lib/core/models/user.dart
import 'package:json_annotation/json_annotation.dart';

part 'user.g.dart';

@JsonSerializable()
class User {
  final String id;
  final String username;
  final String email;
  final String? profileImageUrl;
  final String? bio;
  final Location? location;
  final List<String> preferences;
  final UserStats stats;
  final DateTime createdAt;

  const User({
    required this.id,
    required this.username,
    required this.email,
    this.profileImageUrl,
    this.bio,
    this.location,
    this.preferences = const [],
    required this.stats,
    required this.createdAt,
  });

  factory User.fromJson(Map<String, dynamic> json) => _$UserFromJson(json);
  Map<String, dynamic> toJson() => _$UserToJson(this);
}

@JsonSerializable()
class UserStats {
  final int reviewsCount;
  final int followersCount;
  final int followingCount;
  final double averageRating;

  const UserStats({
    required this.reviewsCount,
    required this.followersCount,
    required this.followingCount,
    required this.averageRating,
  });

  factory UserStats.fromJson(Map<String, dynamic> json) => _$UserStatsFromJson(json);
  Map<String, dynamic> toJson() => _$UserStatsToJson(this);
}

---

// lib/core/models/business.dart
import 'package:json_annotation/json_annotation.dart';

part 'business.g.dart';

@JsonSerializable()
class Business {
  final String id;
  final String name;
  final String description;
  final BusinessType type;
  final Location location;
  final List<String> images;
  final ContactInfo contact;
  final List<Promotion> currentPromotions;
  final BusinessStats stats;
  final List<String> tags;
  final Map<String, dynamic> hours;
  final double priceRange;

  const Business({
    required this.id,
    required this.name,
    required this.description,
    required this.type,
    required this.location,
    required this.images,
    required this.contact,
    required this.currentPromotions,
    required this.stats,
    required this.tags,
    required this.hours,
    required this.priceRange,
  });

  factory Business.fromJson(Map<String, dynamic> json) => _$BusinessFromJson(json);
  Map<String, dynamic> toJson() => _$BusinessToJson(this);
}

@JsonSerializable()
class Location {
  final double latitude;
  final double longitude;
  final String address;
  final String city;
  final String state;
  final String zipCode;

  const Location({
    required this.latitude,
    required this.longitude,
    required this.address,
    required this.city,
    required this.state,
    required this.zipCode,
  });

  factory Location.fromJson(Map<String, dynamic> json) => _$LocationFromJson(json);
  Map<String, dynamic> toJson() => _$LocationToJson(this);
}

enum BusinessType { restaurant, bar, activity, entertainment, retail }

---

// lib/core/models/review.dart
import 'package:json_annotation/json_annotation.dart';

part 'review.g.dart';

@JsonSerializable()
class Review {
  final String id;
  final String userId;
  final String businessId;
  final double rating;
  final String content;
  final List<String> images;
  final List<String> tags;
  final ReviewSentiment sentiment;
  final DateTime createdAt;
  final int likesCount;
  final bool isVerified;

  const Review({
    required this.id,
    required this.userId,
    required this.businessId,
    required this.rating,
    required this.content,
    required this.images,
    required this.tags,
    required this.sentiment,
    required this.createdAt,
    required this.likesCount,
    required this.isVerified,
  });

  factory Review.fromJson(Map<String, dynamic> json) => _$ReviewFromJson(json);
  Map<String, dynamic> toJson() => _$ReviewToJson(this);
}

@JsonSerializable()
class ReviewSentiment {
  final double positivityScore;
  final List<String> positiveKeywords;
  final List<String> negativeKeywords;
  final String overallTone;

  const ReviewSentiment({
    required this.positivityScore,
    required this.positiveKeywords,
    required this.negativeKeywords,
    required this.overallTone,
  });

  factory ReviewSentiment.fromJson(Map<String, dynamic> json) => _$ReviewSentimentFromJson(json);
  Map<String, dynamic> toJson() => _$ReviewSentimentToJson(this);
}

---

// lib/features/home/screens/home_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../widgets/story_bar.dart';
import '../widgets/business_feed.dart';
import '../widgets/promotion_carousel.dart';
import '../../discover/widgets/quick_filters.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      body: CustomScrollView(
        slivers: [
          SliverAppBar(
            floating: true,
            title: const Text(
              'Crave',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 24,
              ),
            ),
            actions: [
              IconButton(
                icon: const Icon(Icons.notifications),
                onPressed: () => _showNotifications(context),
              ),
              IconButton(
                icon: const Icon(Icons.chat),
                onPressed: () => _openChat(context),
              ),
            ],
          ),
          const SliverToBoxAdapter(
            child: Column(
              children: [
                StoryBar(),
                SizedBox(height: 16),
                PromotionCarousel(),
                SizedBox(height: 16),
                QuickFilters(),
                SizedBox(height: 8),
              ],
            ),
          ),
          const BusinessFeed(),
        ],
      ),
    );
  }

  void _showNotifications(BuildContext context) {
    // Navigate to notifications
  }

  void _openChat(BuildContext context) {
    // Navigate to chat/messages
  }
}

---

// lib/features/home/widgets/business_feed.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'business_card.dart';
import '../providers/home_provider.dart';

class BusinessFeed extends ConsumerWidget {
  const BusinessFeed({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final feedState = ref.watch(homeFeedProvider);
    
    return feedState.when(
      loading: () => const SliverFillRemaining(
        child: Center(child: CircularProgressIndicator()),
      ),
      error: (error, stack) => SliverFillRemaining(
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline, size: 48, color: Colors.grey),
              const SizedBox(height: 16),
              Text('Failed to load businesses: $error'),
              ElevatedButton(
                onPressed: () => ref.refresh(homeFeedProvider),
                child: const Text('Retry'),
              ),
            ],
          ),
        ),
      ),
      data: (businesses) => SliverList(
        delegate: SliverChildBuilderDelegate(
          (context, index) => BusinessCard(business: businesses[index]),
          childCount: businesses.length,
        ),
      ),
    );
  }
}

---

// lib/features/discover/screens/discover_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../widgets/search_bar.dart';
import '../widgets/category_grid.dart';
import '../widgets/trending_section.dart';
import '../widgets/nearby_section.dart';

class DiscoverScreen extends ConsumerStatefulWidget {
  const DiscoverScreen({super.key});

  @override
  ConsumerState<DiscoverScreen> createState() => _DiscoverScreenState();
}

class _DiscoverScreenState extends ConsumerState<DiscoverScreen> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: CustomScrollView(
        slivers: [
          SliverAppBar(
            floating: true,
            title: const Text('Discover'),
            bottom: const PreferredSize(
              preferredSize: Size.fromHeight(60),
              child: Padding(
                padding: EdgeInsets.all(16.0),
                child: CustomSearchBar(),
              ),
            ),
          ),
          const SliverToBoxAdapter(
            child: Column(
              children: [
                CategoryGrid(),
                SizedBox(height: 24),
                TrendingSection(),
                SizedBox(height: 24),
                NearbySection(),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

---

// lib/features/profile/screens/profile_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../widgets/profile_header.dart';
import '../widgets/stats_row.dart';
import '../widgets/review_grid.dart';
import '../../auth/providers/auth_provider.dart';

class ProfileScreen extends ConsumerWidget {
  const ProfileScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final user = ref.watch(currentUserProvider);
    
    return Scaffold(
      appBar: AppBar(
        title: Text(user?.username ?? 'Profile'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => _openSettings(context),
          ),
          PopupMenuButton<String>(
            onSelected: (value) => _handleMenuAction(context, ref, value),
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'insights',
                child: Text('Business Insights'),
              ),
              const PopupMenuItem(
                value: 'preferences',
                child: Text('Preferences'),
              ),
              const PopupMenuItem(
                value: 'logout',
                child: Text('Logout'),
              ),
            ],
          ),
        ],
      ),
      body: user == null
          ? const Center(child: CircularProgressIndicator())
          : CustomScrollView(
              slivers: [
                SliverToBoxAdapter(
                  child: Column(
                    children: [
                      ProfileHeader(user: user),
                      const SizedBox(height: 16),
                      StatsRow(stats: user.stats),
                      const SizedBox(height: 24),
                    ],
                  ),
                ),
                ReviewGrid(userId: user.id),
              ],
            ),
    );
  }

  void _openSettings(BuildContext context) {
    // Navigate to settings
  }

  void _handleMenuAction(BuildContext context, WidgetRef ref, String action) {
    switch (action) {
      case 'insights':
        // Navigate to business insights
        break;
      case 'preferences':
        // Navigate to preferences
        break;
      case 'logout':
        ref.read(authProvider.notifier).logout();
        break;
    }
  }
}

---

// lib/features/business/screens/business_detail_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/models/business.dart';
import '../widgets/business_header.dart';
import '../widgets/promotion_section.dart';
import '../widgets/reviews_section.dart';
import '../widgets/business_actions.dart';

class BusinessDetailScreen extends ConsumerWidget {
  final String businessId;
  
  const BusinessDetailScreen({
    super.key,
    required this.businessId,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // This would use a provider to fetch business details
    // final businessAsync = ref.watch(businessDetailProvider(businessId));
    
    return Scaffold(
      body: CustomScrollView(
        slivers: [
          const SliverAppBar(
            expandedHeight: 300,
            pinned: true,
            flexibleSpace: FlexibleSpaceBar(
              // Business image carousel would go here
            ),
          ),
          SliverToBoxAdapter(
            child: Column(
              children: [
                // BusinessHeader(business: business),
                const SizedBox(height: 16),
                // PromotionSection(promotions: business.currentPromotions),
                const SizedBox(height: 16),
                // BusinessActions(business: business),
                const SizedBox(height: 24),
              ],
            ),
          ),
          // ReviewsSection(businessId: businessId),
        ],
      ),
    );
  }
}

---

// lib/core/services/location_service.dart
import 'package:geolocator/geolocator.dart';
import 'package:permission_handler/permission_handler.dart';

class LocationService {
  static Position? _currentPosition;
  
  static Future<void> initialize() async {
    await _requestLocationPermission();
    await getCurrentLocation();
  }

  static Future<void> _requestLocationPermission() async {
    final status = await Permission.location.request();
    if (status.isDenied) {
      throw Exception('Location permission denied');
    }
  }

  static Future<Position?> getCurrentLocation() async {
    try {
      _currentPosition = await Geolocator.getCurrentPosition(
        desiredAccuracy: LocationAccuracy.high,
      );
      return _currentPosition;
    } catch (e) {
      print('Error getting location: $e');
      return null;
    }
  }

  static Position? get currentPosition => _currentPosition;

  static double calculateDistance(
    double startLatitude,
    double startLongitude,
    double endLatitude,
    double endLongitude,
  ) {
    return Geolocator.distanceBetween(
      startLatitude,
      startLongitude,
      endLatitude,
      endLongitude,
    );
  }

  static Future<void> startLocationTracking() async {
    // Implement background location tracking for notifications
    Geolocator.getPositionStream(
      locationSettings: const LocationSettings(
        accuracy: LocationAccuracy.high,
        distanceFilter: 100, // Update every 100 meters
      ),
    ).listen((Position position) {
      _currentPosition = position;
      // Trigger nearby business checks
    });
  }
}

---

// lib/core/services/notification_service.dart
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:firebase_messaging/firebase_messaging.dart';

class NotificationService {
  static final _localNotifications = FlutterLocalNotificationsPlugin();
  
  static Future<void> initialize() async {
    // Initialize local notifications
    const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
    const iosSettings = DarwinInitializationSettings();
    const settings = InitializationSettings(
      android: androidSettings,
      iOS: iosSettings,
    );
    
    await _localNotifications.initialize(settings);
    
    // Setup Firebase messaging
    await FirebaseMessaging.instance.requestPermission(
      alert: true,
      badge: true,
      sound: true,
      provisional: false,
    );
    
    // Handle background messages
    FirebaseMessaging.onBackgroundMessage(_firebaseMessagingBackgroundHandler);
    
    // Handle foreground messages
    FirebaseMessaging.onMessage.listen(_handleForegroundMessage);
  }

  static Future<void> showProximityNotification({
    required String title,
    required String body,
    required String businessId,
  }) async {
    const details = NotificationDetails(
      android: AndroidNotificationDetails(
        'proximity',
        'Nearby Businesses',
        description: 'Notifications for nearby businesses and promotions',
        importance: Importance.high,
        priority: Priority.high,
      ),
      iOS: DarwinNotificationDetails(),
    );
    
    await _localNotifications.show(
      0,
      title,
      body,
      details,
      payload: businessId,
    );
  }

  static Future<void> _firebaseMessagingBackgroundHandler(RemoteMessage message) async {
    // Handle background notifications
  }

  static void _handleForegroundMessage(RemoteMessage message) {
    // Handle foreground notifications
  }
}

---

// lib/core/router/app_router.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../features/auth/screens/login_screen.dart';
import '../../features/home/screens/home_screen.dart';
import '../../features/discover/screens/discover_screen.dart';
import '../../features/profile/screens/profile_screen.dart';
import '../../features/business/screens/business_detail_screen.dart';
import '../navigation/main_navigation.dart';
import '../navigation/auth_guard.dart';

final appRouterProvider = Provider<GoRouter>((ref) {
  return GoRouter(
    initialLocation: '/',
    routes: [
      GoRoute(
        path: '/login',
        builder: (context, state) => const LoginScreen(),
      ),
      ShellRoute(
        builder: (context, state, child) => MainNavigation(child: child),
        routes: [
          GoRoute(
            path: '/',
            builder: (context, state) => const HomeScreen(),
          ),
          GoRoute(
            path: '/discover',
            builder: (context, state) => const DiscoverScreen(),
          ),
          GoRoute(
            path: '/profile',
            builder: (context, state) => const ProfileScreen(),
          ),
          GoRoute(
            path: '/business/:id',
            builder: (context, state) => BusinessDetailScreen(
              businessId: state.pathParameters['id']!,
            ),
          ),
        ],
      ),
    ],
    redirect: (context, state) {
      // Add authentication logic here
      return null;
    },
  );
});

---

// lib/core/navigation/main_navigation.dart
import 'package:flutter/material.dart';

class MainNavigation extends StatefulWidget {
  final Widget child;
  
  const MainNavigation({
    super.key,
    required this.child,
  });

  @override
  State<MainNavigation> createState() => _MainNavigationState();
}

class _MainNavigationState extends State<MainNavigation> {
  int _currentIndex = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: widget.child,
      bottomNavigationBar: BottomNavigationBar(
        type: BottomNavigationBarType.fixed,
        currentIndex: _currentIndex,
        onTap: (index) {
          setState(() => _currentIndex = index);
          _navigateToPage(index);
        },
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.home),
            label: 'Home',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.search),
            label: 'Discover',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.add_box_outlined),
            label: 'Create',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.favorite_border),
            label: 'Favorites',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.person),
            label: 'Profile',
          ),
        ],
      ),
    );
  }

  void _navigateToPage(int index) {
    switch (index) {
      case 0:
        // Navigate to home
        break;
      case 1:
        // Navigate to discover
        break;
      case 2:
        // Navigate to create review/post
        break;
      case 3:
        // Navigate to favorites
        break;
      case 4:
        // Navigate to profile
        break;
    }
  }
}

---

// lib/features/home/providers/home_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/models/business.dart';

final homeFeedProvider = FutureProvider<List<Business>>((ref) async {
  // Simulate API call - replace with actual service
  await Future.delayed(const Duration(seconds: 1));
  
  return [
    Business(
      id: '1',
      name: 'The Local Brew',
      description: 'Craft beer and artisanal food in the heart of downtown',
      type: BusinessType.bar,
      location: const Location(
        latitude: 30.2672,
        longitude: -97.7431,
        address: '123 Main St',
        city: 'Austin',
        state: 'TX',
        zipCode: '78701',
      ),
      images: ['https://via.placeholder.com/400x300'],
      contact: const ContactInfo(
        phone: '(512) 123-4567',
        email: 'info@localbrew.com',
        website: 'https://localbrew.com',
      ),
      currentPromotions: [],
      stats: const BusinessStats(
        rating: 4.5,
        reviewCount: 247,
        checkInCount: 892,
        favoriteCount: 156,
      ),
      tags: ['craft beer', 'local', 'live music'],
      hours: {},
      priceRange: 2.5,
    ),
    // Add more sample businesses...
  ];
});

---

// lib/features/auth/providers/auth_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/models/user.dart';

final authProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  return AuthNotifier();
});

final currentUserProvider = Provider<User?>((ref) {
  final authState = ref.watch(authProvider);
  return authState.maybeWhen(
    authenticated: (user) => user,
    orElse: () => null,
  );
});

class AuthNotifier extends StateNotifier<AuthState> {
  AuthNotifier() : super(const AuthState.initial());

  Future<void> login(String email, String password) async {
    state = const AuthState.loading();
    
    try {
      // Simulate login - replace with Firebase Auth
      await Future.delayed(const Duration(seconds: 1));
      
      final user = User(
        id: '1',
        username: 'foodie_explorer',
        email: email,
        profileImageUrl: 'https://via.placeholder.com/150',
        bio: 'Love discovering local gems!',
        preferences: ['bars', 'restaurants', 'live music'],
        stats: const UserStats(
          reviewsCount: 23,
          followersCount: 156,
          followingCount: 89,
          averageRating: 4.2,
        ),
        createdAt: DateTime.now().subtract(const Duration(days: 365)),
      );
      
      state = AuthState.authenticated(user);
    } catch (e) {
      state = AuthState.error(e.toString());
    }
  }

  Future<void> logout() async {
    state = const AuthState.initial();
  }
}

class AuthState {
  const AuthState._();
  
  const factory AuthState.initial() = _Initial;
  const factory AuthState.loading() = _Loading;
  const factory AuthState.authenticated(User user) = _Authenticated;
  const factory AuthState.error(String message) = _Error;

  T when<T>({
    required T Function() initial,
    required T Function() loading,
    required T Function(User user) authenticated,
    required T Function(String message) error,
  }) {
    if (this is _Initial) return initial();
    if (this is _Loading) return loading();
    if (this is _Authenticated) return authenticated((this as _Authenticated).user);
    if (this is _Error) return error((this as _Error).message);
    throw Exception('Unknown state');
  }

  T? maybeWhen<T>({
    T Function()? initial,
    T Function()? loading,
    T Function(User user)? authenticated,
    T Function(String message)? error,
    required T Function() orElse,
  }) {
    if (this is _Initial && initial != null) return initial();
    if (this is _Loading && loading != null) return loading();
    if (this is _Authenticated && authenticated != null) return authenticated((this as _Authenticated).user);
    if (this is _Error && error != null) return error((this as _Error).message);
    return orElse();
  }
}

class _Initial extends AuthState {
  const _Initial() : super._();
}

class _Loading extends AuthState {
  const _Loading() : super._();
}

class _Authenticated extends AuthState {
  final User user;
  const _Authenticated(this.user) : super._();
}

class _Error extends AuthState {
  final String message;
  const _Error(this.message) : super._();
}

---

// lib/features/home/widgets/business_card.dart
import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import '../../../core/models/business.dart';

class BusinessCard extends StatelessWidget {
  final Business business;

  const BusinessCard({
    super.key,
    required this.business,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Business Header
          ListTile(
            leading: CircleAvatar(
              backgroundImage: business.images.isNotEmpty 
                  ? CachedNetworkImageProvider(business.images.first)
                  : null,
              child: business.images.isEmpty 
                  ? Text(business.name[0].toUpperCase())
                  : null,
            ),
            title: Text(
              business.name,
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            subtitle: Text('${business.location.city} • ${business.type.name}'),
            trailing: IconButton(
              icon: const Icon(Icons.more_vert),
              onPressed: () => _showBusinessOptions(context),
            ),
          ),
          
          // Business Image
          if (business.images.isNotEmpty)
            AspectRatio(
              aspectRatio: 16 / 9,
              child: CachedNetworkImage(
                imageUrl: business.images.first,
                fit: BoxFit.cover,
                placeholder: (context, url) => Container(
                  color: Colors.grey[300],
                  child: const Center(child: CircularProgressIndicator()),
                ),
                errorWidget: (context, url, error) => Container(
                  color: Colors.grey[300],
                  child: const Icon(Icons.error),
                ),
              ),
            ),
          
          // Action Buttons
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.favorite_border),
                  onPressed: () => _toggleFavorite(),
                ),
                IconButton(
                  icon: const Icon(Icons.chat_bubble_outline),
                  onPressed: () => _openReviews(context),
                ),
                IconButton(
                  icon: const Icon(Icons.share),
                  onPressed: () => _shareBusinesse(),
                ),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.bookmark_border),
                  onPressed: () => _saveForLater(),
                ),
              ],
            ),
          ),
          
          // Business Info
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(Icons.star, color: Colors.amber, size: 16),
                    Text(' ${business.stats.rating} '),
                    Text('(${business.stats.reviewCount} reviews)'),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  business.description,
                  style: const TextStyle(fontSize: 14),
                ),
                if (business.currentPromotions.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: Theme.of(context).primaryColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      '🎉 Special Offer Available!',
                      style: TextStyle(
                        color: Theme.of(context).primaryColor,
                        fontWeight: FontWeight.w500,
                        fontSize: 12,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showBusinessOptions(BuildContext context) {
    showModalBottomSheet(
      context: context,
      builder: (context) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          ListTile(
            leading: const Icon(Icons.info),
            title: const Text('View Details'),
            onTap: () => Navigator.pop(context),
          ),
          ListTile(
            leading: const Icon(Icons.directions),
            title: const Text('Get Directions'),
            onTap: () => Navigator.pop(context),
          ),
          ListTile(
            leading: const Icon(Icons.phone),
            title: const Text('Call Business'),
            onTap: () => Navigator.pop(context),
          ),
        ],
      ),
    );
  }

  void _toggleFavorite() {
    // Implement favorite logic
  }

  void _openReviews(BuildContext context) {
    // Navigate to reviews
  }

  void _shareBusinesse() {
    // Implement sharing
  }

  void _saveForLater() {
    // Implement save for later
  }
}

---

// README.md
# Crave - Local Business Discovery App

A Flutter-based mobile application that connects users with local bars, restaurants, and activities, similar to Instagram but focused on local business discovery and promotion.

## Features

### Core Features
- **Instagram-like Interface**: Stories, feed, and social interactions
- **Local Business Discovery**: Find nearby bars, restaurants, and activities
- **Geo-location Based**: Location tracking and proximity notifications
- **Review System**: Transparent review analysis with sentiment tracking
- **Promotion Hub**: Business specials and happy hour advertisements
- **Gamified Onboarding**: LLM-powered personalized recommendations

### Business Features (B2B)
- **Business Analytics**: Insights based on user reviews and web data
- **Sentiment Analysis**: AI-powered review sentiment tracking
- **Performance Metrics**: Comprehensive business performance dashboards
- **Promotion Management**: Tools for creating and managing specials

### User Features (B2C)
- **Personalized Feed**: AI-driven content recommendations
- **Social Reviews**: Share experiences with photos and ratings
- **Discovery Tools**: Advanced search and filtering options
- **Social Features**: Follow businesses and users, like and comment
- **Notifications**: Location-based promotion alerts

## Technical Stack

- **Framework**: Flutter 3.10+
- **State Management**: Riverpod
- **Navigation**: GoRouter
- **Backend**: Firebase (Auth, Analytics, Messaging)
- **Maps**: Google Maps Flutter
- **Location**: Geolocator
- **Notifications**: Firebase Messaging + Local Notifications
- **Storage**: Hive (local) + Firebase (cloud)
- **AI/ML**: Integration ready for LLM services

## Project Structure

```
lib/
├── core/
│   ├── config/          # App configuration
│   ├── models/          # Data models
│   ├── services/        # Core services
│   ├── theme/           # App theming
│   ├── router/          # Navigation setup
│   └── navigation/      # Navigation widgets
├── features/
│   ├── auth/            # Authentication
│   ├── home/            # Home feed
│   ├── discover/        # Discovery & search
│   ├── business/        # Business details
│   ├── profile/         # User profiles
│   ├── reviews/         # Review system
│   └── notifications/   # Notification handling
└── shared/
    ├── widgets/         # Reusable widgets
    └── utils/           # Utilities
```

## Setup Instructions

1. **Prerequisites**
   - Flutter 3.10+
   - Firebase project setup
   - Google Maps API key

2. **Installation**
   ```bash
   flutter pub get
   dart run build_runner build
   ```

3. **Configuration**
   - Add Firebase config files
   - Update Google Maps API key in `app_config.dart`
   - Configure permissions in platform files

4. **Running**
   ```bash
   flutter run
   ```

## Key Components

### Location Services
- Real-time location tracking
- Proximity-based notifications  
- Distance calculations for business discovery

### AI Integration
- Sentiment analysis for reviews
- Personalized recommendations
- Gamified user onboarding

### Business Analytics
- Review sentiment tracking
- User engagement metrics
- Performance insights dashboard

### Monetization
- Ad revenue integration ready
- Business promotion tools
- Analytics for advertisers

## Roadmap

- [ ] MVP with core features
- [ ] LLM integration for recommendations
- [ ] Advanced analytics dashboard
- [ ] Business onboarding portal
- [ ] Revenue optimization
- [ ] Scale to Netflix-level recommendations

This foundation provides a solid starting point for building your Instagram-like local business discovery platform!