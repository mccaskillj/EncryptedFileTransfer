#define VECTOR_SIZE 128
#define NAME_SIZE 10
#define HASH_SIZE 128

typedef struct dataNode
{
	struct dataNode *prev;
	struct dataNode *next;
	char *name;
	int size;
	char *hash;
}dataNode;

typedef struct dataHead
{
	dataNode *first;
	dataNode *last;
	int size;
	char *vector;
	int numFiles;
}dataHead;
