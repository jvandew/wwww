from google.cloud import datastore


def main():
  datastore_client = datastore.Client()
  partial_key = datastore_client.key('rsvp')

  saved_count = 0
  print('enter rsvp data, \'done\' to quit on invited count or first name')

  invited_count_input = input('invited count: ').lower()
  while invited_count_input != 'done':
    invited_count = int(invited_count_input)
    invited = []

    first_name = input('first name: ').lower()
    while first_name != 'done':
      last_name = input('last name: ').lower()
      invited.append({
        'first_name': first_name,
        'last_name': last_name,
      })
      first_name = input('first name: ').lower()

    key = datastore_client.allocate_ids(partial_key, 1)[0]
    rsvp = datastore.Entity(
      key=key,
      exclude_from_indexes=['invited_count'],
    )
    rsvp['invited'] = invited
    rsvp['invited_count'] = invited_count
    datastore_client.put(rsvp)
    saved_count += 1

    invited_count_input = input('invited_count: ').lower()

  print('created {} rsvp entries'.format(saved_count))

if __name__ == '__main__':
  main()
