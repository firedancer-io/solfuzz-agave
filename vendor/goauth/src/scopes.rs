// https://developers.google.com/identity/protocols/googlescopes

#![allow(dead_code)]

#[derive(Clone, Debug)]
pub enum Scope {
    Activity,
    AdexchangeBuyer,
    AdexchangeSeller,
    AdexchangeSellerReadOnly,
    AdminDataTransfer,
    AdminDataTransferReadOnly,
    AdminDirectoryCustomer,
    AdminDirectoryCustomerReadOnly,
    AdminDirectoryDeviceChromeOs,
    AdminDirectoryDeviceChromeOsReadOnly,
    AdminDirectoryDeviceMobile,
    AdminDirectoryDeviceMobileAction,
    AdminDirectoryDeviceMobileReadOnly,
    AdminDirectoryDomain,
    AdminDirectoryDomainReadOnly,
    AdminDirectoryGroup,
    AdminDirectoryGroupMember,
    AdminDirectoryGroupMemberReadOnly,
    AdminDirectoryGroupReadOnly,
    AdminDirectoryNotifications,
    AdminDirectoryOrgUnit,
    AdminDirectoryOrgUnitReadOnly,
    AdminDirectoryResourceCalendar,
    AdminDirectoryResourceCalendarReadOnly,
    AdminDirectoryRoleManagement,
    AdminDirectoryRoleManagementReadOnly,
    AdminDirectoryUser,
    AdminDirectoryUserAlias,
    AdminDirectoryUserAliasReadOnly,
    AdminDirectoryUserReadOnly,
    AdminDirectoryUserSchema,
    AdminDirectoryUserSchemaReadOnly,
    AdminDirectoryUserSecurity,
    AdminReportsAuditReadOnly,
    AdminReportsUsageReadOnly,
    AdSense,
    AdSenseHost,
    AdSenseReadOnly,
    Analytics,
    AnalyticsEdit,
    AnalyticsManageUsers,
    AnalyticsManageUsersReadOnly,
    AnalyticsProvision,
    AnalyticsReadOnly,
    AndroidEnterprise,
    AndroidPublisher,
    AppEngineAdmin,
    AppsGroupsMigration,
    AppsGroupsSettings,
    AppsLicensing,
    AppsOrder,
    AppsOrderReadOnly,
    AppState,
    BigTableData,
    BigTableDataReadOnly,
    BigQuery,
    BigQueryInsertdata,
    Blogger,
    BloggerReadOnly,
    Books,
    Calendar,
    CalendarFeeds,
    CalendarReadOnly,
    ClassroomCourses,
    ClassroomCoursesReadOnly,
    ClassroomCourseworkMe,
    ClassroomCourseworkMeReadOnly,
    ClassroomCourseWorkReadOnly,
    ClassroomCourseworkStudents,
    ClassroomCourseworkStudentsReadOnly,
    ClassroomProfileEmails,
    ClassroomProfilePhotos,
    ClassroomRosters,
    ClassroomRostersReadOnly,
    ClassroomStudentSubmissionsMeReadOnly,
    ClassroomStudentSubmissionsStudentsReadOnly,
    CloudDebugger,
    CloudPlatform,
    CloudPlatformReadOnly,
    CloudRuntimeConfig,
    CloudUserAccounts,
    CloudUserAccountsReadOnly,
    Compute,
    ComputeReadOnly,
    Contacts,
    ContactsReadOnly,
    Content,
    DataStore,
    Ddmconversions,
    DevStorageFullControl,
    DevStorageReadOnly,
    DevStorageReadWrite,
    Dfareporting,
    Dfatrafficking,
    DoubleclickSearch,
    Drive,
    DriveAppdata,
    DriveFile,
    DriveMetadata,
    DriveMetadataReadOnly,
    DrivePhotosReadOnly,
    DriveReadOnly,
    DriveScripts,
    Firebase,
    FirebaseReadOnly,
    FirebaseCloudMessaging,
    FitnessActivityRead,
    FitnessActivityWrite,
    FitnessBodyRead,
    FitnessBodyWrite,
    FitnessLocationRead,
    FitnessLocationWrite,
    FitnessNutritionRead,
    FitnessNutritionWrite,
    Forms,
    FormsCurrentOnly,
    FusionTables,
    FusionTablesReadOnly,
    Games,
    Genomics,
    GenomicsReadOnly,
    GlassLocation,
    GlassTimeline,
    Gmail,
    GmailCompose,
    GmailInsert,
    GmailLabels,
    GmailMetadata,
    GmailModify,
    GmailReadOnly,
    GmailSend,
    GmailSettingsBasic,
    GmailSettingsSharing,
    Groups,
    LoggingAdmin,
    LoggingRead,
    LoggingWrite,
    M8Feeds,
    MalachiteIngestion,
    ManufacturerCenter,
    Monitoring,
    MonitoringRead,
    MonitoringWrite,
    NdevClouddnsReadOnly,
    NdevClouddnsReadwrite,
    NdevCloudman,
    NdevCloudmanReadOnly,
    PlayMoviesPartnerReadOnly,
    PlusCirclesRead,
    PlusCirclesWrite,
    PlusLogin,
    PlusMe,
    PlusMediaUpload,
    PlusProfilesRead,
    PlusStreamRead,
    PlusStreamWrite,
    Prediction,
    Presentations,
    PresentationsReadOnly,
    PubSub,
    ReplicaPool,
    ReplicaPoolReadOnly,
    Servicecontrol,
    ServiceManagement,
    ServiceManagementReadOnly,
    SiteVerification,
    SiteVerificationVerifyOnly,
    SpreadSheets,
    SpreadSheetsReadOnly,
    SQLServiceAdmin,
    TagManagerDeleteContainers,
    TagManagerEditContainers,
    TagManagerEditContainerVersions,
    TagManagerManageAccounts,
    TagManagerManageUsers,
    TagManagerPublish,
    TagManagerReadOnly,
    TaskQueue,
    TaskQueueConsumer,
    Tasks,
    TasksReadOnly,
    TraceAppend,
    TraceReadOnly,
    URLShortener,
    UserAddressesRead,
    UserBirthdayRead,
    UserEmailsRead,
    UserInfoEmail,
    UserInfoProfile,
    UserLocationBeaconRegistry,
    UserPhoneNumbersRead,
    WebMasters,
    WebMastersReadOnly,
    YouTube,
    YouTubeAnalyticsMonetaryReadOnly,
    YouTubeAnalyticsReadOnly,
    YouTubeForceSSL,
    YouTubepartner,
    YouTubepartnerChannelAudit,
    YouTubeReadOnly,
    YouTubeUpload,
    CloudLanguage,
}

impl Scope {
    pub fn url(&self) -> String {
        match *self {
            Scope::Activity => String::from("https://www.googleapis.com/auth/activity"),
            Scope::AdexchangeBuyer => {
                String::from("https://www.googleapis.com/auth/adexchange.buyer")
            }
            Scope::AdexchangeSeller => {
                String::from("https://www.googleapis.com/auth/adexchange.seller")
            }
            Scope::AdexchangeSellerReadOnly => {
                String::from("https://www.googleapis.com/auth/adexchange.seller.readonly")
            }
            Scope::AdminDataTransfer => {
                String::from("https://www.googleapis.com/auth/admin.datatransfer")
            }
            Scope::AdminDataTransferReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.datatransfer.readonly")
            }
            Scope::AdminDirectoryCustomer => {
                String::from("https://www.googleapis.com/auth/admin.directory.customer")
            }
            Scope::AdminDirectoryCustomerReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.directory.customer.readonly")
            }
            Scope::AdminDirectoryDeviceChromeOs => {
                String::from("https://www.googleapis.com/auth/admin.directory.device.chromeos")
            }
            Scope::AdminDirectoryDeviceChromeOsReadOnly => String::from(
                "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
            ),
            Scope::AdminDirectoryDeviceMobile => {
                String::from("https://www.googleapis.com/auth/admin.directory.device.mobile")
            }
            Scope::AdminDirectoryDeviceMobileAction => {
                String::from("https://www.googleapis.com/auth/admin.directory.device.mobile.action")
            }
            Scope::AdminDirectoryDeviceMobileReadOnly => String::from(
                "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
            ),
            Scope::AdminDirectoryDomain => {
                String::from("https://www.googleapis.com/auth/admin.directory.domain")
            }
            Scope::AdminDirectoryDomainReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.directory.domain.readonly")
            }
            Scope::AdminDirectoryGroup => {
                String::from("https://www.googleapis.com/auth/admin.directory.group")
            }
            Scope::AdminDirectoryGroupMember => {
                String::from("https://www.googleapis.com/auth/admin.directory.group.member")
            }
            Scope::AdminDirectoryGroupMemberReadOnly => String::from(
                "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            ),
            Scope::AdminDirectoryGroupReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.directory.group.readonly")
            }
            Scope::AdminDirectoryNotifications => {
                String::from("https://www.googleapis.com/auth/admin.directory.notifications")
            }
            Scope::AdminDirectoryOrgUnit => {
                String::from("https://www.googleapis.com/auth/admin.directory.orgunit")
            }
            Scope::AdminDirectoryOrgUnitReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.directory.orgunit.readonly")
            }
            Scope::AdminDirectoryResourceCalendar => {
                String::from("https://www.googleapis.com/auth/admin.directory.resource.calendar")
            }
            Scope::AdminDirectoryResourceCalendarReadOnly => String::from(
                "https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly",
            ),
            Scope::AdminDirectoryRoleManagement => {
                String::from("https://www.googleapis.com/auth/admin.directory.rolemanagement")
            }
            Scope::AdminDirectoryRoleManagementReadOnly => String::from(
                "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
            ),
            Scope::AdminDirectoryUser => {
                String::from("https://www.googleapis.com/auth/admin.directory.user")
            }
            Scope::AdminDirectoryUserAlias => {
                String::from("https://www.googleapis.com/auth/admin.directory.user.alias")
            }
            Scope::AdminDirectoryUserAliasReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.directory.user.alias.readonly")
            }
            Scope::AdminDirectoryUserReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.directory.user.readonly")
            }
            Scope::AdminDirectoryUserSchema => {
                String::from("https://www.googleapis.com/auth/admin.directory.userschema")
            }
            Scope::AdminDirectoryUserSchemaReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.directory.userschema.readonly")
            }
            Scope::AdminDirectoryUserSecurity => {
                String::from("https://www.googleapis.com/auth/admin.directory.user.security")
            }
            Scope::AdminReportsAuditReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.reports.audit.readonly")
            }
            Scope::AdminReportsUsageReadOnly => {
                String::from("https://www.googleapis.com/auth/admin.reports.usage.readonly")
            }
            Scope::AdSense => String::from("https://www.googleapis.com/auth/adsense"),
            Scope::AdSenseHost => String::from("https://www.googleapis.com/auth/adsensehost"),
            Scope::AdSenseReadOnly => {
                String::from("https://www.googleapis.com/auth/adsense.readonly")
            }
            Scope::Analytics => String::from("https://www.googleapis.com/auth/analytics"),
            Scope::AnalyticsEdit => String::from("https://www.googleapis.com/auth/analytics.edit"),
            Scope::AnalyticsManageUsers => {
                String::from("https://www.googleapis.com/auth/analytics.manage.users")
            }
            Scope::AnalyticsManageUsersReadOnly => {
                String::from("https://www.googleapis.com/auth/analytics.manage.users.readonly")
            }
            Scope::AnalyticsProvision => {
                String::from("https://www.googleapis.com/auth/analytics.provision")
            }
            Scope::AnalyticsReadOnly => {
                String::from("https://www.googleapis.com/auth/analytics.readonly")
            }
            Scope::AndroidEnterprise => {
                String::from("https://www.googleapis.com/auth/androidenterprise")
            }
            Scope::AndroidPublisher => {
                String::from("https://www.googleapis.com/auth/androidpublisher")
            }
            Scope::AppEngineAdmin => {
                String::from("https://www.googleapis.com/auth/appengine.admin")
            }
            Scope::AppsGroupsMigration => {
                String::from("https://www.googleapis.com/auth/apps.groups.migration")
            }
            Scope::AppsGroupsSettings => {
                String::from("https://www.googleapis.com/auth/apps.groups.settings")
            }
            Scope::AppsLicensing => String::from("https://www.googleapis.com/auth/apps.licensing"),
            Scope::AppsOrder => String::from("https://www.googleapis.com/auth/apps.order"),
            Scope::AppsOrderReadOnly => {
                String::from("https://www.googleapis.com/auth/apps.order.readonly")
            }
            Scope::AppState => String::from("https://www.googleapis.com/auth/appstate"),
            Scope::BigTableData => String::from("https://www.googleapis.com/auth/bigtable.data"),
            Scope::BigTableDataReadOnly => {
                String::from("https://www.googleapis.com/auth/bigtable.data.readonly")
            }
            Scope::BigQuery => String::from("https://www.googleapis.com/auth/bigquery"),
            Scope::BigQueryInsertdata => {
                String::from("https://www.googleapis.com/auth/bigquery.insertdata")
            }
            Scope::Blogger => String::from("https://www.googleapis.com/auth/blogger"),
            Scope::BloggerReadOnly => {
                String::from("https://www.googleapis.com/auth/blogger.readonly")
            }
            Scope::Books => String::from("https://www.googleapis.com/auth/books"),
            Scope::Calendar => String::from("https://www.googleapis.com/auth/calendar"),
            Scope::CalendarFeeds => String::from("https://www.google.com/calendar/feeds"),
            Scope::CalendarReadOnly => {
                String::from("https://www.googleapis.com/auth/calendar.readonly")
            }
            Scope::ClassroomCourses => {
                String::from("https://www.googleapis.com/auth/classroom.courses")
            }
            Scope::ClassroomCoursesReadOnly => {
                String::from("https://www.googleapis.com/auth/classroom.courses.readonly")
            }
            Scope::ClassroomCourseworkMe => {
                String::from("https://www.googleapis.com/auth/classroom.coursework.me")
            }
            Scope::ClassroomCourseworkMeReadOnly => {
                String::from("https://www.googleapis.com/auth/classroom.coursework.me.readonly")
            }
            Scope::ClassroomCourseWorkReadOnly => {
                String::from("https://www.googleapis.com/auth/classroom.course-work.readonly")
            }
            Scope::ClassroomCourseworkStudents => {
                String::from("https://www.googleapis.com/auth/classroom.coursework.students")
            }
            Scope::ClassroomCourseworkStudentsReadOnly => String::from(
                "https://www.googleapis.com/auth/classroom.coursework.students.readonly",
            ),
            Scope::ClassroomProfileEmails => {
                String::from("https://www.googleapis.com/auth/classroom.profile.emails")
            }
            Scope::ClassroomProfilePhotos => {
                String::from("https://www.googleapis.com/auth/classroom.profile.photos")
            }
            Scope::ClassroomRosters => {
                String::from("https://www.googleapis.com/auth/classroom.rosters")
            }
            Scope::ClassroomRostersReadOnly => {
                String::from("https://www.googleapis.com/auth/classroom.rosters.readonly")
            }
            Scope::ClassroomStudentSubmissionsMeReadOnly => String::from(
                "https://www.googleapis.com/auth/classroom.student-submissions.me.readonly",
            ),
            Scope::ClassroomStudentSubmissionsStudentsReadOnly => String::from(
                "https://www.googleapis.com/auth/classroom.student-submissions.students.readonly",
            ),
            Scope::CloudDebugger => String::from("https://www.googleapis.com/auth/cloud_debugger"),
            Scope::CloudPlatform => String::from("https://www.googleapis.com/auth/cloud-platform"),
            Scope::CloudPlatformReadOnly => {
                String::from("https://www.googleapis.com/auth/cloud-platform.read-only")
            }
            Scope::CloudRuntimeConfig => {
                String::from("https://www.googleapis.com/auth/cloudruntimeconfig")
            }
            Scope::CloudUserAccounts => {
                String::from("https://www.googleapis.com/auth/cloud.useraccounts")
            }
            Scope::CloudUserAccountsReadOnly => {
                String::from("https://www.googleapis.com/auth/cloud.useraccounts.readonly")
            }
            Scope::Compute => String::from("https://www.googleapis.com/auth/compute"),
            Scope::ComputeReadOnly => {
                String::from("https://www.googleapis.com/auth/compute.readonly")
            }
            Scope::Contacts => String::from("https://www.googleapis.com/auth/contacts"),
            Scope::ContactsReadOnly => {
                String::from("https://www.googleapis.com/auth/contacts.readonly")
            }
            Scope::Content => String::from("https://www.googleapis.com/auth/content"),
            Scope::DataStore => String::from("https://www.googleapis.com/auth/datastore"),
            Scope::Ddmconversions => String::from("https://www.googleapis.com/auth/ddmconversions"),
            Scope::DevStorageFullControl => {
                String::from("https://www.googleapis.com/auth/devstorage.full_control")
            }
            Scope::DevStorageReadOnly => {
                String::from("https://www.googleapis.com/auth/devstorage.read_only")
            }
            Scope::DevStorageReadWrite => {
                String::from("https://www.googleapis.com/auth/devstorage.read_write")
            }
            Scope::Dfareporting => String::from("https://www.googleapis.com/auth/dfareporting"),
            Scope::Dfatrafficking => String::from("https://www.googleapis.com/auth/dfatrafficking"),
            Scope::DoubleclickSearch => {
                String::from("https://www.googleapis.com/auth/doubleclicksearch")
            }
            Scope::Drive => String::from("https://www.googleapis.com/auth/drive"),
            Scope::DriveAppdata => String::from("https://www.googleapis.com/auth/drive.appdata"),
            Scope::DriveFile => String::from("https://www.googleapis.com/auth/drive.file"),
            Scope::DriveMetadata => String::from("https://www.googleapis.com/auth/drive.metadata"),
            Scope::DriveMetadataReadOnly => {
                String::from("https://www.googleapis.com/auth/drive.metadata.readonly")
            }
            Scope::DrivePhotosReadOnly => {
                String::from("https://www.googleapis.com/auth/drive.photos.readonly")
            }
            Scope::DriveReadOnly => String::from("https://www.googleapis.com/auth/drive.readonly"),
            Scope::DriveScripts => String::from("https://www.googleapis.com/auth/drive.scripts"),
            Scope::Firebase => String::from("https://www.googleapis.com/auth/firebase"),
            Scope::FirebaseReadOnly => {
                String::from("https://www.googleapis.com/auth/firebase.readonly")
            }
            Scope::FirebaseCloudMessaging => {
                String::from("https://www.googleapis.com/auth/firebase.messaging")
            }
            Scope::FitnessActivityRead => {
                String::from("https://www.googleapis.com/auth/fitness.activity.read")
            }
            Scope::FitnessActivityWrite => {
                String::from("https://www.googleapis.com/auth/fitness.activity.write")
            }
            Scope::FitnessBodyRead => {
                String::from("https://www.googleapis.com/auth/fitness.body.read")
            }
            Scope::FitnessBodyWrite => {
                String::from("https://www.googleapis.com/auth/fitness.body.write")
            }
            Scope::FitnessLocationRead => {
                String::from("https://www.googleapis.com/auth/fitness.location.read")
            }
            Scope::FitnessLocationWrite => {
                String::from("https://www.googleapis.com/auth/fitness.location.write")
            }
            Scope::FitnessNutritionRead => {
                String::from("https://www.googleapis.com/auth/fitness.nutrition.read")
            }
            Scope::FitnessNutritionWrite => {
                String::from("https://www.googleapis.com/auth/fitness.nutrition.write")
            }
            Scope::Forms => String::from("https://www.googleapis.com/auth/forms"),
            Scope::FormsCurrentOnly => {
                String::from("https://www.googleapis.com/auth/forms.currentonly")
            }
            Scope::FusionTables => String::from("https://www.googleapis.com/auth/fusiontables"),
            Scope::FusionTablesReadOnly => {
                String::from("https://www.googleapis.com/auth/fusiontables.readonly")
            }
            Scope::Games => String::from("https://www.googleapis.com/auth/games"),
            Scope::Genomics => String::from("https://www.googleapis.com/auth/genomics"),
            Scope::GenomicsReadOnly => {
                String::from("https://www.googleapis.com/auth/genomics.readonly")
            }
            Scope::GlassLocation => String::from("https://www.googleapis.com/auth/glass.location"),
            Scope::GlassTimeline => String::from("https://www.googleapis.com/auth/glass.timeline"),
            Scope::Gmail => String::from("https://mail.google.com/"),
            Scope::GmailCompose => String::from("https://www.googleapis.com/auth/gmail.compose"),
            Scope::GmailInsert => String::from("https://www.googleapis.com/auth/gmail.insert"),
            Scope::GmailLabels => String::from("https://www.googleapis.com/auth/gmail.labels"),
            Scope::GmailMetadata => String::from("https://www.googleapis.com/auth/gmail.metadata"),
            Scope::GmailModify => String::from("https://www.googleapis.com/auth/gmail.modify"),
            Scope::GmailReadOnly => String::from("https://www.googleapis.com/auth/gmail.readonly"),
            Scope::GmailSend => String::from("https://www.googleapis.com/auth/gmail.send"),
            Scope::GmailSettingsBasic => {
                String::from("https://www.googleapis.com/auth/gmail.settings.basic")
            }
            Scope::GmailSettingsSharing => {
                String::from("https://www.googleapis.com/auth/gmail.settings.sharing")
            }
            Scope::Groups => String::from("https://www.googleapis.com/auth/groups"),
            Scope::LoggingAdmin => String::from("https://www.googleapis.com/auth/logging.admin"),
            Scope::LoggingRead => String::from("https://www.googleapis.com/auth/logging.read"),
            Scope::LoggingWrite => String::from("https://www.googleapis.com/auth/logging.write"),
            Scope::M8Feeds => String::from("https://www.google.com/m8/feeds"),
            Scope::MalachiteIngestion => {
                String::from("https://www.googleapis.com/auth/malachite-ingestion")
            }
            Scope::ManufacturerCenter => {
                String::from("https://www.googleapis.com/auth/manufacturercenter")
            }
            Scope::Monitoring => String::from("https://www.googleapis.com/auth/monitoring"),
            Scope::MonitoringRead => {
                String::from("https://www.googleapis.com/auth/monitoring.read")
            }
            Scope::MonitoringWrite => {
                String::from("https://www.googleapis.com/auth/monitoring.write")
            }
            Scope::NdevClouddnsReadOnly => {
                String::from("https://www.googleapis.com/auth/ndev.clouddns.readonly")
            }
            Scope::NdevClouddnsReadwrite => {
                String::from("https://www.googleapis.com/auth/ndev.clouddns.readwrite")
            }
            Scope::NdevCloudman => String::from("https://www.googleapis.com/auth/ndev.cloudman"),
            Scope::NdevCloudmanReadOnly => {
                String::from("https://www.googleapis.com/auth/ndev.cloudman.readonly")
            }
            Scope::PlayMoviesPartnerReadOnly => {
                String::from("https://www.googleapis.com/auth/playmovies_partner.readonly")
            }
            Scope::PlusCirclesRead => {
                String::from("https://www.googleapis.com/auth/plus.circles.read")
            }
            Scope::PlusCirclesWrite => {
                String::from("https://www.googleapis.com/auth/plus.circles.write")
            }
            Scope::PlusLogin => String::from("https://www.googleapis.com/auth/plus.login"),
            Scope::PlusMe => String::from("https://www.googleapis.com/auth/plus.me"),
            Scope::PlusMediaUpload => {
                String::from("https://www.googleapis.com/auth/plus.media.upload")
            }
            Scope::PlusProfilesRead => {
                String::from("https://www.googleapis.com/auth/plus.profiles.read")
            }
            Scope::PlusStreamRead => {
                String::from("https://www.googleapis.com/auth/plus.stream.read")
            }
            Scope::PlusStreamWrite => {
                String::from("https://www.googleapis.com/auth/plus.stream.write")
            }
            Scope::Prediction => String::from("https://www.googleapis.com/auth/prediction"),
            Scope::Presentations => String::from("https://www.googleapis.com/auth/presentations"),
            Scope::PresentationsReadOnly => {
                String::from("https://www.googleapis.com/auth/presentations.readonly")
            }
            Scope::PubSub => String::from("https://www.googleapis.com/auth/pubsub"),
            Scope::ReplicaPool => String::from("https://www.googleapis.com/auth/replicapool"),
            Scope::ReplicaPoolReadOnly => {
                String::from("https://www.googleapis.com/auth/replicapool.readonly")
            }
            Scope::Servicecontrol => String::from("https://www.googleapis.com/auth/servicecontrol"),
            Scope::ServiceManagement => {
                String::from("https://www.googleapis.com/auth/service.management")
            }
            Scope::ServiceManagementReadOnly => {
                String::from("https://www.googleapis.com/auth/service.management.readonly")
            }
            Scope::SiteVerification => {
                String::from("https://www.googleapis.com/auth/siteverification")
            }
            Scope::SiteVerificationVerifyOnly => {
                String::from("https://www.googleapis.com/auth/siteverification.verify_only")
            }
            Scope::SpreadSheets => String::from("https://www.googleapis.com/auth/spreadsheets"),
            Scope::SpreadSheetsReadOnly => {
                String::from("https://www.googleapis.com/auth/spreadsheets.readonly")
            }
            Scope::SQLServiceAdmin => {
                String::from("https://www.googleapis.com/auth/sqlservice.admin")
            }
            Scope::TagManagerDeleteContainers => {
                String::from("https://www.googleapis.com/auth/tagmanager.delete.containers")
            }
            Scope::TagManagerEditContainers => {
                String::from("https://www.googleapis.com/auth/tagmanager.edit.containers")
            }
            Scope::TagManagerEditContainerVersions => {
                String::from("https://www.googleapis.com/auth/tagmanager.edit.containerversions")
            }
            Scope::TagManagerManageAccounts => {
                String::from("https://www.googleapis.com/auth/tagmanager.manage.accounts")
            }
            Scope::TagManagerManageUsers => {
                String::from("https://www.googleapis.com/auth/tagmanager.manage.users")
            }
            Scope::TagManagerPublish => {
                String::from("https://www.googleapis.com/auth/tagmanager.publish")
            }
            Scope::TagManagerReadOnly => {
                String::from("https://www.googleapis.com/auth/tagmanager.readonly")
            }
            Scope::TaskQueue => String::from("https://www.googleapis.com/auth/taskqueue"),
            Scope::TaskQueueConsumer => {
                String::from("https://www.googleapis.com/auth/taskqueue.consumer")
            }
            Scope::Tasks => String::from("https://www.googleapis.com/auth/tasks"),
            Scope::TasksReadOnly => String::from("https://www.googleapis.com/auth/tasks.readonly"),
            Scope::TraceAppend => String::from("https://www.googleapis.com/auth/trace.append"),
            Scope::TraceReadOnly => String::from("https://www.googleapis.com/auth/trace.readonly"),
            Scope::URLShortener => String::from("https://www.googleapis.com/auth/urlshortener"),
            Scope::UserAddressesRead => {
                String::from("https://www.googleapis.com/auth/user.addresses.read")
            }
            Scope::UserBirthdayRead => {
                String::from("https://www.googleapis.com/auth/user.birthday.read")
            }
            Scope::UserEmailsRead => {
                String::from("https://www.googleapis.com/auth/user.emails.read")
            }
            Scope::UserInfoEmail => String::from("https://www.googleapis.com/auth/userinfo.email"),
            Scope::UserInfoProfile => {
                String::from("https://www.googleapis.com/auth/userinfo.profile")
            }
            Scope::UserLocationBeaconRegistry => {
                String::from("https://www.googleapis.com/auth/userlocation.beacon.registry")
            }
            Scope::UserPhoneNumbersRead => {
                String::from("https://www.googleapis.com/auth/user.phonenumbers.read")
            }
            Scope::WebMasters => String::from("https://www.googleapis.com/auth/webmasters"),
            Scope::WebMastersReadOnly => {
                String::from("https://www.googleapis.com/auth/webmasters.readonly")
            }
            Scope::YouTube => String::from("https://www.googleapis.com/auth/youtube"),
            Scope::YouTubeAnalyticsMonetaryReadOnly => {
                String::from("https://www.googleapis.com/auth/yt-analytics-monetary.readonly")
            }
            Scope::YouTubeAnalyticsReadOnly => {
                String::from("https://www.googleapis.com/auth/yt-analytics.readonly")
            }
            Scope::YouTubeForceSSL => {
                String::from("https://www.googleapis.com/auth/youtube.force-ssl")
            }
            Scope::YouTubepartner => String::from("https://www.googleapis.com/auth/youtubepartner"),
            Scope::YouTubepartnerChannelAudit => {
                String::from("https://www.googleapis.com/auth/youtubepartner-channel-audit")
            }
            Scope::YouTubeReadOnly => {
                String::from("https://www.googleapis.com/auth/youtube.readonly")
            }
            Scope::YouTubeUpload => String::from("https://www.googleapis.com/auth/youtube.upload"),
            Scope::CloudLanguage => String::from("https://www.googleapis.com/auth/cloud-language")
        }
    }
}
